"""Terraform-plan claim-extraction tests: exact claims (kind + value +
resource-address location) from the committed ``terraform show -json``
fixtures, plus the conservative skip rules shared with the API-document
extractors — non-google resources, request-time constructs and malformed
fields yield no claim, never a guess."""

import json
from pathlib import Path

import pytest

from gcp_grounding.claims import KINDS, Claim
from gcp_grounding.tf_claims import terraform_plan_claims

POLICIES = Path(__file__).parent / "fixtures" / "gcp" / "policies"


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def member_change(address: str, after, actions=("create",), *, mode="managed",
                  rtype="google_project_iam_member",
                  provider="registry.terraform.io/hashicorp/google") -> dict:
    return {
        "address": address,
        "mode": mode,
        "type": rtype,
        "name": address.rsplit(".", 1)[-1],
        "provider_name": provider,
        "change": {"actions": list(actions),
                   "before": None if actions == ("create",) else {},
                   "after": after},
    }


# -- committed fixtures: exact claims --------------------------------------


def test_tf_plan_good_exact_claims():
    assert terraform_plan_claims(load("tf_plan_good.json")) == [
        Claim("resource_type_ref", "google_project_iam_member",
              "google_project_iam_member.etl_bq_jobs"),
        Claim("role", "roles/bigquery.jobUser", "google_project_iam_member.etl_bq_jobs.role"),
        Claim("principal", "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com",
              "google_project_iam_member.etl_bq_jobs.member"),
        Claim("resource_type_ref", "google_org_policy_policy",
              "google_org_policy_policy.no_sa_keys"),
        Claim("constraint", "constraints/iam.disableServiceAccountKeyCreation",
              "google_org_policy_policy.no_sa_keys.name"),
        Claim("constraint_value", "constraints/iam.disableServiceAccountKeyCreation",
              "google_org_policy_policy.no_sa_keys.spec[0].rules[0].enforce", is_list=False),
    ]


def test_tf_plan_bad_exact_claims():
    # Extraction does not judge: the hallucinated role, the ghost service
    # account and the misspelled constraint all still become claims — the
    # reasoner is what refutes them against the snapshot.
    assert terraform_plan_claims(load("tf_plan_bad.json")) == [
        Claim("resource_type_ref", "google_project_iam_member",
              "google_project_iam_member.bq_reader"),
        Claim("role", "roles/bigquery.reader", "google_project_iam_member.bq_reader.role"),
        Claim("principal", "group:data-eng@acme.example",
              "google_project_iam_member.bq_reader.member"),
        Claim("resource_type_ref", "google_project_iam_member",
              "google_project_iam_member.ghost_sa"),
        Claim("role", "roles/storage.objectViewer", "google_project_iam_member.ghost_sa.role"),
        Claim("principal", "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com",
              "google_project_iam_member.ghost_sa.member"),
        Claim("resource_type_ref", "google_org_policy_policy",
              "google_org_policy_policy.serial_port"),
        Claim("constraint", "constraints/compute.disableSerialPortAcces",
              "google_org_policy_policy.serial_port.name"),
        Claim("constraint_value", "constraints/compute.disableSerialPortAcces",
              "google_org_policy_policy.serial_port.spec[0].rules[0].enforce", is_list=False),
    ]


def test_tf_plan_full_exact_claims():
    # planned_values (root module then module.audit) drives the order; the
    # mirroring resource_changes entries are deduplicated by address, so only
    # the delete-only deprecated_ci — absent from planned_values — is appended,
    # and with after=null it claims nothing beyond its type reference.
    assert terraform_plan_claims(load("tf_plan_full.json")) == [
        Claim("resource_type_ref", "google_project_iam_binding",
              "google_project_iam_binding.viewers"),
        Claim("role", "roles/bigquery.dataViewer", "google_project_iam_binding.viewers.role"),
        Claim("principal", "group:data-eng@acme.example",
              "google_project_iam_binding.viewers.members[0]"),
        Claim("principal", "user:alice@acme.example",
              "google_project_iam_binding.viewers.members[1]"),
        Claim("resource_type_ref", "google_project_iam_custom_role",
              "google_project_iam_custom_role.deployer"),
        Claim("permission", "bigquery.job.create",
              "google_project_iam_custom_role.deployer.permissions[0]"),
        Claim("permission", "storage.objects.get",
              "google_project_iam_custom_role.deployer.permissions[1]"),
        Claim("permission", "storage.objects.list",
              "google_project_iam_custom_role.deployer.permissions[2]"),
        Claim("resource_type_ref", "google_project_iam_member",
              "google_project_iam_member.etl"),
        Claim("role", "roles/bigquery.jobUser", "google_project_iam_member.etl.role"),
        Claim("principal", "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com",
              "google_project_iam_member.etl.member"),
        Claim("cel", 'request.time < timestamp("2027-01-01T00:00:00Z")',
              "google_project_iam_member.etl.condition[0].expression"),
        Claim("resource_type_ref", "google_project_iam_policy",
              "google_project_iam_policy.authoritative"),
        Claim("role", "roles/bigquery.reader",
              "google_project_iam_policy.authoritative.policy_data.bindings[0].role"),
        Claim("principal", "user:bob@acme.example",
              "google_project_iam_policy.authoritative.policy_data.bindings[0].members[0]"),
        Claim("resource_type_ref", "google_org_policy_policy",
              "module.audit.google_org_policy_policy.no_serial_ports"),
        Claim("constraint", "constraints/compute.disableSerialPortAccess",
              "module.audit.google_org_policy_policy.no_serial_ports.name"),
        Claim("constraint_value", "constraints/compute.disableSerialPortAccess",
              "module.audit.google_org_policy_policy.no_serial_ports.spec[0].rules[0].enforce",
              is_list=False),
        Claim("resource_type_ref", "google_org_policy_policy",
              "module.audit.google_org_policy_policy.vm_external_ip"),
        Claim("constraint", "constraints/compute.vmExternalIpAccess",
              "module.audit.google_org_policy_policy.vm_external_ip.name"),
        Claim("constraint_value", "constraints/compute.vmExternalIpAccess",
              "module.audit.google_org_policy_policy.vm_external_ip.spec[0].rules[0].deny_all",
              is_list=True),
        Claim("resource_type_ref", "google_project_iam_member",
              "google_project_iam_member.deprecated_ci"),
    ]


# -- planned_values vs resource_changes ------------------------------------


def test_planned_values_only_plan_yields_full_claims():
    full = load("tf_plan_full.json")
    del full["resource_changes"]
    claims = terraform_plan_claims(full)
    # Everything except the delete-only resource, which lives in
    # resource_changes alone.
    assert Claim("role", "roles/bigquery.dataViewer",
                 "google_project_iam_binding.viewers.role") in claims
    assert not any(c.location.startswith("google_project_iam_member.deprecated_ci")
                   for c in claims)


def test_resource_changes_only_plan_yields_full_claims():
    # Same claims as the full plan — only the resource order differs, since
    # resource_changes is sorted by address while planned_values appends the
    # delete-only resource last.
    full = load("tf_plan_full.json")
    del full["planned_values"]
    claims = terraform_plan_claims(full)
    assert set(claims) == set(terraform_plan_claims(load("tf_plan_full.json")))
    assert len(claims) == len(set(claims))


def test_duplicate_addresses_across_sections_claim_once():
    claims = terraform_plan_claims(load("tf_plan_full.json"))
    assert len(claims) == len(set(claims))


def test_deleted_resource_claims_only_its_type_reference():
    claims = terraform_plan_claims({"resource_changes": [member_change(
        "google_project_iam_member.gone", None, actions=("delete",))]})
    assert claims == [Claim("resource_type_ref", "google_project_iam_member",
                            "google_project_iam_member.gone")]


def test_deposed_delete_does_not_swallow_the_replacement_create():
    # create_before_destroy: terraform lists the deposed object's delete
    # entry (change.after null, "deposed" key set) and the created object's
    # entry at the same address. With the delete listed first it must not
    # claim the address — the create's role/principal claims survive.
    deposed = member_change("google_project_iam_member.x", None, actions=("delete",))
    deposed["deposed"] = "abc123"
    create = member_change("google_project_iam_member.x",
                           {"role": "roles/viewer", "member": "user:alice@acme.example"})
    claims = terraform_plan_claims({"resource_changes": [deposed, create]})
    assert claims == [
        Claim("resource_type_ref", "google_project_iam_member",
              "google_project_iam_member.x"),
        Claim("role", "roles/viewer", "google_project_iam_member.x.role"),
        Claim("principal", "user:alice@acme.example",
              "google_project_iam_member.x.member"),
    ]


def test_deposed_only_delete_still_claims_its_type_reference():
    # A deposed delete with no surviving entry at its address is an ordinary
    # destroy: the type reference is still claimed, nothing more.
    deposed = member_change("google_project_iam_member.gone", None, actions=("delete",))
    deposed["deposed"] = "abc123"
    claims = terraform_plan_claims({"resource_changes": [deposed]})
    assert claims == [Claim("resource_type_ref", "google_project_iam_member",
                            "google_project_iam_member.gone")]


# -- provider / mode filtering ---------------------------------------------


def test_non_google_resources_yield_no_claims():
    assert terraform_plan_claims({"resource_changes": [member_change(
        "aws_iam_role.x", {"role": "roles/viewer"}, rtype="aws_iam_role",
        provider="registry.terraform.io/hashicorp/aws")]}) == []


def test_data_mode_resources_are_skipped():
    assert terraform_plan_claims({"resource_changes": [member_change(
        "data.google_project.this", {"project_id": "acme-prod"}, mode="data",
        rtype="google_project")]}) == []


def test_invented_google_resource_type_is_still_claimed():
    # The whole point of resource_type_ref: a plausible-but-nonexistent type
    # (plural 'bindings') becomes a claim the reasoner can refute.
    claims = terraform_plan_claims({"resource_changes": [member_change(
        "google_project_iam_bindings.oops", {"role": "roles/viewer"},
        rtype="google_project_iam_bindings")]})
    assert claims == [Claim("resource_type_ref", "google_project_iam_bindings",
                            "google_project_iam_bindings.oops")]


def test_unhandled_google_type_yields_type_reference_only():
    claims = terraform_plan_claims({"resource_changes": [member_change(
        "google_storage_bucket.data", {"name": "acme-data"},
        rtype="google_storage_bucket")]})
    assert claims == [Claim("resource_type_ref", "google_storage_bucket",
                            "google_storage_bucket.data")]


# -- conservative skips shared with the API-document extractors ------------


def test_public_member_yields_public_principal_claim():
    # An allUsers member is no longer dropped: it rides through the shared
    # iam_policy_claims extractor as a 'public_principal' grant carrying the
    # role, re-anchored onto the resource address.
    claims = terraform_plan_claims({"resource_changes": [member_change(
        "google_project_iam_member.public", {"role": "roles/viewer", "member": "allUsers"})]})
    assert claims == [
        Claim("resource_type_ref", "google_project_iam_member",
              "google_project_iam_member.public"),
        Claim("role", "roles/viewer", "google_project_iam_member.public.role"),
        Claim.of("public_principal", "allUsers", "google_project_iam_member.public.member",
                 polarity="grant", role="roles/viewer"),
    ]


def test_tag_condition_yields_no_cel_claim():
    claims = terraform_plan_claims({"resource_changes": [member_change(
        "google_project_iam_member.tagged",
        {"role": "roles/viewer", "member": "user:alice@acme.example",
         "condition": [{"expression": "resource.matchTag('tagKeys/123', 'prod')"}]})]})
    assert not any(c.kind == "cel" for c in claims)


def test_unparsable_policy_data_yields_type_reference_only():
    claims = terraform_plan_claims({"resource_changes": [member_change(
        "google_project_iam_policy.broken", {"policy_data": "not json {"},
        rtype="google_project_iam_policy")]})
    assert claims == [Claim("resource_type_ref", "google_project_iam_policy",
                            "google_project_iam_policy.broken")]


def test_custom_role_without_permission_list_yields_type_reference_only():
    claims = terraform_plan_claims({"resource_changes": [member_change(
        "google_project_iam_custom_role.empty", {"role_id": "x", "permissions": None},
        rtype="google_project_iam_custom_role")]})
    assert claims == [Claim("resource_type_ref", "google_project_iam_custom_role",
                            "google_project_iam_custom_role.empty")]


def test_org_policy_ambiguous_rule_yields_constraint_claim_only():
    claims = terraform_plan_claims({"resource_changes": [member_change(
        "google_org_policy_policy.both",
        {"name": "projects/acme-prod/policies/compute.disableSerialPortAccess",
         "spec": [{"rules": [{"enforce": "TRUE",
                              "values": [{"allowed_values": ["x"]}]}]}]},
        rtype="google_org_policy_policy")]})
    assert claims == [
        Claim("resource_type_ref", "google_org_policy_policy",
              "google_org_policy_policy.both"),
        Claim("constraint", "constraints/compute.disableSerialPortAccess",
              "google_org_policy_policy.both.name"),
    ]


def test_org_policy_values_rule_is_list_typed():
    claims = terraform_plan_claims({"resource_changes": [member_change(
        "google_org_policy_policy.allowlist",
        {"name": "projects/acme-prod/policies/compute.vmExternalIpAccess",
         "spec": [{"rules": [{"enforce": None, "allow_all": None, "deny_all": None,
                              "values": [{"allowed_values":
                                          ["projects/acme-prod/zones/us-central1-a/instances/vm"]}]}]}]},
        rtype="google_org_policy_policy")]})
    assert claims[-1] == Claim(
        "constraint_value", "constraints/compute.vmExternalIpAccess",
        "google_org_policy_policy.allowlist.spec[0].rules[0].values", is_list=True)


def test_org_policy_without_constraint_name_yields_type_reference_only():
    claims = terraform_plan_claims({"resource_changes": [member_change(
        "google_org_policy_policy.nameless", {"parent": "projects/acme-prod"},
        rtype="google_org_policy_policy")]})
    assert claims == [Claim("resource_type_ref", "google_org_policy_policy",
                            "google_org_policy_policy.nameless")]


# -- input validation ------------------------------------------------------


def test_empty_plan_yields_no_claims():
    assert terraform_plan_claims({}) == []
    assert terraform_plan_claims({"format_version": "1.2"}) == []


def test_non_mapping_plan_is_rejected():
    with pytest.raises(ValueError):
        terraform_plan_claims(["not", "a", "plan"])


def test_new_kinds_are_registered():
    assert "permission" in KINDS
    assert "resource_type_ref" in KINDS
