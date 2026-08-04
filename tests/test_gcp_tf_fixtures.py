"""Shape smoke test for the two committed JSON terraform fixtures.

``tests/fixtures/gcp/tf/estate.tfstate`` and ``tests/fixtures/gcp/tf/
estate_plan.json`` describe the SAME estate as ``tests/fixtures/gcp/
estate_snapshot.json``, spelled two ways — a v4 state file and a
``terraform show -json`` plan. Both are hand-written: the ``terraform`` binary
is not installed on this machine and nothing here may require it.

THIS MODULE IMPORTS NOTHING FROM ``gcp_grounding.tfsource`` ON PURPOSE, so it
can land before any reader exists. It is a cheap smoke test, NOT the
requirement. The real gates are downstream and are strong: the mapper tasks
assert the records these files produce are EQUAL to the loaded estate fixture's,
the state and plan readers are driven entirely from these two files, and the
capture task carries the both-directions fixture-consistency pin over this whole
tree. A wrong byte here fails there, by name.

What is asserted below is only the structural surface every one of those readers
depends on: the v4 envelope and its five deliberate hazards (no composed
``address``, a data-mode entry, a deposed generation, both index-key types), the
plan's four input shapes, the action vocabulary, and the presence of the three
grep-able secret sentinels the redaction tests exist to remove.
"""

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
TF_DIR = FIXTURES / "tf"
STATE_PATH = TF_DIR / "estate.tfstate"
PLAN_PATH = TF_DIR / "estate_plan.json"

#: Plaintext sentinels planted in both files. Every redaction test proves it
#: removed these; the fixture's job is to make sure there is something to
#: remove, so a redactor that does nothing cannot pass by accident.
SECRET_SENTINELS = (
    "FIXTURE-SECRET-DO-NOT-LEAK",
    "FIXTURE-SECRET-BY-NAME",
    "FIXTURE-PLAN-SECRET",
)

STATE = json.loads(STATE_PATH.read_text(encoding="utf-8"))
PLAN = json.loads(PLAN_PATH.read_text(encoding="utf-8"))


def _instances():
    for entry in STATE["resources"]:
        for inst in entry["instances"]:
            yield entry, inst


def _module_addresses(module):
    """Every resource address in a plan values-representation module tree."""
    for resource in module.get("resources") or ():
        yield resource["address"]
    for child in module.get("child_modules") or ():
        yield from _module_addresses(child)


def _actions(entry):
    return tuple(entry["change"]["actions"])


def _normalized_action(entry):
    """The reader's action vocabulary: the two-element delete-then-create pair
    that terraform emits for a replacement maps to the single name ``replace``."""
    actions = _actions(entry)
    if len(actions) == 2 and set(actions) == {"delete", "create"}:
        return "replace"
    return actions[0] if len(actions) == 1 else "+".join(actions)


# -- both files exist and parse -------------------------------------------


def test_both_fixtures_parse_as_json():
    assert isinstance(STATE, dict) and STATE
    assert isinstance(PLAN, dict) and PLAN


def test_the_tf_tree_is_the_only_terraform_fixture_tree():
    # The design names exactly one terraform fixture tree. A second one is how
    # two readers end up grounded against two different estates.
    assert TF_DIR.is_dir()
    assert not (FIXTURES / "terraform").exists()


# -- the v4 state envelope ------------------------------------------------


def test_state_is_version_4_with_no_format_version():
    assert STATE["version"] == 4
    # `format_version` is the PLAN's discriminator. A tfstate carrying one
    # would make content-based classification ambiguous.
    assert "format_version" not in STATE
    assert STATE["terraform_version"] == "1.9.5"
    assert isinstance(STATE["serial"], int)
    assert isinstance(STATE["lineage"], str) and STATE["lineage"]
    assert STATE["check_results"] is None
    assert isinstance(STATE["outputs"], dict)


def test_every_state_resource_entry_has_the_v4_keys_and_no_address():
    assert STATE["resources"], "an empty resources array proves nothing"
    for entry in STATE["resources"]:
        for key in ("mode", "type", "name", "provider", "instances"):
            assert key in entry, f"{entry.get('type')}.{entry.get('name')}: {key}"
        # HAZARD 2: v4 has no `address` key anywhere — the reader composes it
        # from the optional module prefix, the type, the name and the index.
        assert "address" not in entry
        assert isinstance(entry["instances"], list) and entry["instances"]


def test_the_real_bracketed_provider_spelling_is_used():
    # A naive rsplit("/", 1)[-1] on this yields 'google"]', which matches no
    # allowlist, so every google resource silently disappears.
    providers = {entry["provider"] for entry in STATE["resources"]}
    assert 'provider["registry.terraform.io/hashicorp/google"]' in providers
    assert 'provider["registry.terraform.io/hashicorp/google-beta"]' in providers
    for provider in providers:
        assert provider.startswith('provider["registry.terraform.io/')


def test_exactly_one_state_entry_is_a_data_source():
    data = [e for e in STATE["resources"] if e["mode"] == "data"]
    assert len(data) == 1
    assert data[0]["type"] == "google_project"


def test_state_carries_a_deposed_generation_beside_its_live_instance():
    deposed = [(entry, inst) for entry, inst in _instances() if "deposed" in inst]
    assert len(deposed) == 1
    entry, inst = deposed[0]
    assert inst["deposed"] == "abc12345"
    # The live instance at the SAME address must still be there: the failure
    # mode this fixture exists for is silent loss of the live object behind a
    # stale one, so the entry carries both generations.
    live = [i for i in entry["instances"] if "deposed" not in i]
    assert len(live) == 1
    assert live[0]["attributes"]["source_ranges"] == ["10.0.0.0/8"]
    assert inst["attributes"]["source_ranges"] == ["10.0.0.0/16"]


def test_state_carries_both_index_key_types():
    keys = [inst["index_key"] for _, inst in _instances() if "index_key" in inst]
    strings = [k for k in keys if isinstance(k, str)]
    ints = [k for k in keys if isinstance(k, int) and not isinstance(k, bool)]
    assert "prod" in strings
    assert 0 in ints


def test_state_carries_a_module_qualified_entry():
    modules = {e.get("module") for e in STATE["resources"]}
    assert "module.net" in modules


def test_state_carries_the_sensitive_attributes_cty_path():
    sa = [e for e in STATE["resources"] if e["type"] == "google_service_account"]
    assert len(sa) == 1
    inst = sa[0]["instances"][0]
    assert inst["sensitive_attributes"] == [
        [{"type": "get_attr", "value": "private_key"}]]
    attrs = inst["attributes"]
    assert attrs["private_key"] == "FIXTURE-SECRET-DO-NOT-LEAK"
    # Named by NO cty path: only the attribute-name heuristic can catch it.
    assert attrs["password"] == "FIXTURE-SECRET-BY-NAME"
    # The over-redaction fixture: a realistic KMS resource name is not a secret
    # and must survive verbatim.
    assert attrs["kms_key_name"].startswith("projects/acme-prod/locations/")
    assert "keyRings" in attrs["kms_key_name"]


def test_state_has_a_google_resource_with_no_mapper():
    types = {e["type"] for e in STATE["resources"]}
    assert "google_sql_database_instance" in types


def test_state_outputs_carry_one_sensitive_value_in_the_clear():
    sensitive = {name: out for name, out in STATE["outputs"].items()
                 if out.get("sensitive")}
    assert len(sensitive) == 1
    (out,) = sensitive.values()
    # Terraform stores the value in the clear and only marks it. Mirroring
    # that is what makes the outputs arm of the reader worth having.
    assert out["value"] == "FIXTURE-SECRET-DO-NOT-LEAK"


# -- the plan document ----------------------------------------------------


def test_plan_format_version_is_major_1():
    assert PLAN["format_version"].startswith("1.")
    assert PLAN["terraform_version"] == "1.9.5"


def test_plan_carries_prior_state_and_planned_values_root_modules():
    prior = PLAN["prior_state"]["values"]["root_module"]
    planned = PLAN["planned_values"]["root_module"]
    assert prior["resources"]
    assert planned["resources"]
    # ARM 1 recurses child_modules; a nested module is the shape that catches a
    # reader which only reads the root.
    assert prior["child_modules"][0]["address"] == "module.net"
    assert planned["child_modules"][0]["address"] == "module.net"


def test_plan_values_representation_carries_its_own_keys():
    # A DIFFERENT schema from the tfstate: composed `address`, `provider_name`
    # rather than `provider`, `values` rather than `attributes`.
    for resource in PLAN["prior_state"]["values"]["root_module"]["resources"]:
        for key in ("address", "mode", "type", "name", "provider_name",
                    "values", "sensitive_values"):
            assert key in resource, f"{resource.get('address')}: {key}"


def test_plan_actions_cover_the_whole_reader_vocabulary():
    seen = {_normalized_action(e) for e in PLAN["resource_changes"]}
    assert {"no-op", "create", "update", "delete", "replace"} <= seen


def test_plan_delete_entry_has_a_null_after_and_a_full_before():
    deletes = [e for e in PLAN["resource_changes"]
               if _actions(e) == ("delete",) and "deposed" not in e]
    assert deletes
    removed = [e for e in deletes if e["name"] == "deny-ssh-external"]
    assert len(removed) == 1
    ch = removed[0]["change"]
    assert ch["after"] is None
    assert ch["before"] is not None
    # The deletion is a FACT ABOUT WHAT IS BEING REMOVED — the whole rule, not
    # a stub — so a check can say "this removes the deny that blocks tcp/22".
    assert ch["before"]["deny"] == [{"ports": ["22"], "protocol": "tcp"}]
    assert ch["before"]["source_ranges"] == ["0.0.0.0/0"]


def test_plan_create_marks_its_unknowns_instead_of_omitting_them_silently():
    creates = [e for e in PLAN["resource_changes"]
               if _actions(e) == ("create",) and e["name"] == "allow-db-internal"]
    assert len(creates) == 1
    ch = creates[0]["change"]
    unknown = ch["after_unknown"]
    assert unknown, "a create with an empty after_unknown proves nothing"
    # An unknown attribute is OMITTED from `after` entirely, so the mirror is
    # the only thing distinguishing not-yet-known from genuinely-unset.
    for key in ("id", "self_link"):
        assert key not in ch["after"]
        assert unknown[key] is True
    assert "ports" not in ch["after"]["allow"][0]
    assert unknown["allow"][0]["ports"] is True


def test_plan_carries_a_deposed_delete_sharing_an_address_with_a_live_create():
    deposed = [e for e in PLAN["resource_changes"] if "deposed" in e]
    assert len(deposed) == 1
    address = deposed[0]["address"]
    assert deposed[0]["change"]["after"] is None
    live = [e for e in PLAN["resource_changes"]
            if e["address"] == address and "deposed" not in e]
    assert len(live) == 1
    assert _actions(live[0]) == ("create",)


def test_plan_has_a_before_for_a_resource_prior_state_does_not_cover():
    covered = set(_module_addresses(PLAN["prior_state"]["values"]["root_module"]))
    orphans = [e for e in PLAN["resource_changes"]
               if e["change"]["before"] is not None and e["address"] not in covered]
    assert orphans, ("the before-side arm needs input that is not shadowed by "
                     "prior state")
    assert "google_project_iam_member.legacy-viewer" in {
        e["address"] for e in orphans}


def test_plan_marks_one_attribute_sensitive_with_the_plaintext_present():
    marked = []
    for entry in PLAN["resource_changes"]:
        sensitive = entry["change"].get("after_sensitive")
        after = entry["change"].get("after")
        if not isinstance(sensitive, dict) or not isinstance(after, dict):
            continue
        for field, flag in sensitive.items():
            if flag is True and after.get(field) == "FIXTURE-PLAN-SECRET":
                marked.append((entry["address"], field))
    assert marked == [("google_service_account.etl-runner", "private_key")]


def test_plan_carries_one_resource_drift_entry():
    drift = PLAN["resource_drift"]
    assert isinstance(drift, list) and len(drift) == 1
    assert drift[0]["address"] == (
        'module.net.google_compute_firewall.allow-iap-ssh["prod"]')


# -- the redaction sentinels ----------------------------------------------


def test_both_fixtures_carry_every_secret_sentinel():
    for path in (STATE_PATH, PLAN_PATH):
        text = path.read_text(encoding="utf-8")
        for sentinel in SECRET_SENTINELS:
            assert sentinel in text, f"{path.name} lost {sentinel}"
