"""The one HCL and ``.tf.json`` reader: the plan-JSON encoding, the poison
rules, the never-substitute non-goal and the config-directory contract.

THE HEADLINE PIN is :func:`test_main_tf_maps_onto_the_estate_fixtures_records`:
the committed ``main.tf``'s objects, fed STRAIGHT through
``mapping.map_objects``, produce ``firewall_rules``, ``cloud_armor_policies``,
``vpc_sc_perimeters``, ``iam_bindings`` and ``org_policies`` records equal to the
estate fixture's. That is the three-readers-one-mapper proof, and it is what
makes the shared plan-JSON encoding real rather than aspirational.

The two domain mapper modules named in ``mapping.MAP_MODULES`` are separate
tasks and are not in this checkout, so the projections below are registered
through the REAL registry seam — ``mapping.register`` then ``mapping.map_objects``
— rather than substituted for it. Registration keeps the FIRST claimant, and
``register`` resolves ``MAP_MODULES`` before it records anything, so when the
domain mappers land THEY win this pin and it starts testing them instead. The
projections read ``obj.values`` and nothing else, which is exactly the claim
under test: the encoding this reader produces carries everything an estate
record needs, whichever syntax it was read from.

``terraform`` is not installed on this machine and nothing here needs it. The
committed corpus supplies every POSITIVE fixture; degenerate and malformed
inputs are written into ``tmp_path`` per the suite convention.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from gcp_grounding import facts
from gcp_grounding.tfsource import hcl, mapping, normalize

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
HCL_DIR = FIXTURES / "tf" / "hcl"
MAIN_TF = HCL_DIR / "main.tf"
UNRESOLVABLE_TF = HCL_DIR / "unresolvable.tf"
PERIMETER_JSON = HCL_DIR / "perimeter.tf.json"
PROPOSAL_JSON = HCL_DIR / "proposal.tf.json"
ESTATE = FIXTURES / "estate_snapshot.json"

#: main.tf describes project acme-prod; the qualifiers a bare terraform name
#: cannot supply come from the artifact's workspace, never from the resource.
CTX = mapping.MapContext(project="acme-prod")

PINNED_CATEGORIES = ("firewall_rules", "cloud_armor_policies", "vpc_sc_perimeters",
                     "iam_bindings", "org_policies")

#: The EXACT rows main.tf speaks for, so a resource this reader lost is a
#: failure here rather than a shorter table nobody counted. Every one of them is
#: a row the estate fixture stores; ``org_policies`` is the one category where
#: main.tf declares a strict subset (the estate carries two policies main.tf
#: does not, which is why a missing row cannot be caught by set equality alone).
EXPECTED_ROWS = {
    "firewall_rules": ["projects/acme-prod/global/firewalls/allow-health-checks",
                       "projects/acme-prod/global/firewalls/allow-iap-ssh",
                       "projects/acme-prod/global/firewalls/allow-internal",
                       "projects/acme-prod/global/firewalls/deny-ssh-external"],
    "cloud_armor_policies": ["projects/acme-prod/global/securityPolicies/edge-waf"],
    "vpc_sc_perimeters": ["accessPolicies/987/servicePerimeters/prod"],
    "iam_bindings": ["//cloudresourcemanager.googleapis.com/projects/acme-prod"],
    "org_policies": ["projects/acme-prod|constraints/compute.disableSerialPortAccess"],
}

#: THE ONE STATED DISAGREEMENT between the two committed fixtures, pinned rather
#: than excused. ``estate_snapshot.json`` gives allow-health-checks an EMPTY
#: ``layer4`` on purpose — an allow that matches no packet, which the coverage
#: checks need — while ``main.tf`` gives it TWO allow blocks on purpose, as the
#: repeated-block folding fixture. Both files belong to other tasks. The record
#: built from the configuration therefore differs from the stored one in
#: ``layer4`` AND NOWHERE ELSE, and that is asserted from both sides below so a
#: later edit to either fixture surfaces here instead of quietly widening.
HEALTH_CHECKS = "projects/acme-prod/global/firewalls/allow-health-checks"
HEALTH_CHECKS_LAYER4 = [{"protocol": "tcp", "ports": ["80"]},
                        {"protocol": "tcp", "ports": ["443"]}]


@pytest.fixture(scope="module")
def estate():
    return json.loads(ESTATE.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def clean_registry():
    """Registration is import-time and therefore process-global; a projection
    that leaked would answer for every test that ran afterwards."""
    mapping.reset_cache()
    yield
    mapping.reset_cache()


def _objects(path, *, side="current"):
    return {obj.address: obj for obj in hcl.read_file(path, side=side).objects}


def _write(tmp_path, name, text):
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


# -- the projections: one mapper per type, reading obj.values only ------------


def _one(blocks):
    """The single object inside a one-element block list. The plan-JSON encoding
    spells a single block as a one-element LIST, so every mapper unwraps here
    rather than each guessing at the shape."""
    return blocks[0] if isinstance(blocks, list) and blocks else {}


def _map_firewall(obj, ctx):
    values = obj.values
    key = ctx.key("firewall_rules", name=values.get("name"),
                  project=values.get("project"), path=f"{obj.address}.name")
    if facts.is_unresolved(key):
        return ()
    blocks = values.get("allow") or values.get("deny") or []
    layer4 = [{"protocol": normalize.protocol(block.get("protocol"),
                                              path=f"layer4[{index}].protocol"),
               "ports": list(normalize.ports(block.get("ports", []),
                                             path=f"layer4[{index}].ports"))}
              for index, block in enumerate(blocks)]
    record = {
        "action": "allow" if values.get("allow") else "deny",
        "direction": values.get("direction"),
        "disabled": normalize.bool_or(values.get("disabled", False), path="disabled"),
        "layer4": layer4,
        "network": normalize.strip_self_link(values.get("network"), path="network"),
        "priority": normalize.int_or(values.get("priority", 1000), path="priority"),
    }
    for name in ("destination_ranges", "source_ranges"):
        record[name] = list(normalize.cidrs(values.get(name, []), path=name))
    for name in ("source_service_accounts", "source_tags",
                 "target_service_accounts", "target_tags"):
        record[name] = list(normalize.string_list(values.get(name, []), path=name))
    return (facts.Fact(category="firewall_rules", key=key, record=record,
                       source=obj.source, side=obj.side, origin=obj.artifact,
                       address=obj.address),)


def _armor_rule(body):
    match = _one(body.get("match"))
    config = _one(match.get("config"))
    return {
        "action": body.get("action"),
        "match": {"expr": match.get("expr"),
                  "src_ip_ranges": list(normalize.cidrs(config.get("src_ip_ranges", []),
                                                        path="match.config.src_ip_ranges")),
                  "versioned_expr": match.get("versioned_expr")},
        "preview": normalize.bool_or(body.get("preview", False), path="preview"),
        "priority": normalize.int_or(body.get("priority"), path="priority"),
    }


def _map_armor(obj, ctx):
    values = obj.values
    key = ctx.key("cloud_armor_policies", name=values.get("name"),
                  project=values.get("project"), path=f"{obj.address}.name")
    if facts.is_unresolved(key):
        return ()
    record = {"rules": [_armor_rule(rule) for rule in values.get("rule", [])],
              "type": values.get("type")}
    return (facts.Fact(category="cloud_armor_policies", key=key, record=record,
                       source=obj.source, side=obj.side, origin=obj.artifact,
                       address=obj.address),)


def _map_armor_rule(obj, ctx):
    """The STANDALONE rule resource: a ``rules`` FRAGMENT of the policy the
    inline blocks also speak for."""
    values = obj.values
    key = ctx.key("cloud_armor_policies", name=values.get("security_policy"),
                  project=values.get("project"), path=f"{obj.address}.security_policy")
    if facts.is_unresolved(key):
        return ()
    return (facts.Fact(category="cloud_armor_policies", key=key,
                       record={"rules": [_armor_rule(values)]}, fragment="rules",
                       source=obj.source, side=obj.side, origin=obj.artifact,
                       address=obj.address),)


def _map_perimeter(obj, ctx):
    values = obj.values
    key = ctx.key("vpc_sc_perimeters", name=values.get("name"),
                  access_policy=values.get("parent"), path=f"{obj.address}.name")
    if facts.is_unresolved(key):
        return ()
    status = _one(values.get("status"))
    egress = []
    for policy in status.get("egress_policies", []):
        source, target = _one(policy.get("egress_from")), _one(policy.get("egress_to"))
        egress.append({
            "egress_from": {"identities": list(source.get("identities", [])),
                            "identity_type": source.get("identity_type")},
            "egress_to": {
                "operations": [{"method_selectors": [dict(selector) for selector
                                                     in operation.get("method_selectors", [])],
                                "service_name": operation.get("service_name")}
                               for operation in target.get("operations", [])],
                "resources": list(target.get("resources", []))},
        })
    record = {
        "perimeter_type": values.get("perimeter_type"),
        "spec": None if values.get("spec") is None else _one(values.get("spec")),
        "status": {
            "access_levels": list(status.get("access_levels", [])),
            "egress_policies": egress,
            "ingress_policies": list(status.get("ingress_policies", [])),
            "resources": list(status.get("resources", [])),
            "restricted_services": [normalize.restricted_service(service,
                                                                 path="restricted_services")
                                    for service in status.get("restricted_services", [])]},
        "use_explicit_dry_run_spec": normalize.bool_or(
            values.get("use_explicit_dry_run_spec", False),
            path="use_explicit_dry_run_spec"),
    }
    return (facts.Fact(category="vpc_sc_perimeters", key=key, record=record,
                       source=obj.source, side=obj.side, origin=obj.artifact,
                       address=obj.address),)


def _binding_fact(obj, ctx, members):
    values = obj.values
    key = ctx.key("iam_bindings", name=f"projects/{values.get('project')}",
                  path=f"{obj.address}.project")
    if facts.is_unresolved(key):
        return ()
    record = {"bindings": [{"condition": values.get("condition"),
                            "members": [normalize.principal(member, path="members")
                                        for member in members],
                            "role": values.get("role")}]}
    return (facts.Fact(category="iam_bindings", key=key, record=record,
                       fragment="bindings", source=obj.source, side=obj.side,
                       origin=obj.artifact, address=obj.address),)


def _map_iam_binding(obj, ctx):
    return _binding_fact(obj, ctx, obj.values.get("members", []))


def _map_iam_member(obj, ctx):
    return _binding_fact(obj, ctx, [obj.values.get("member")])


def _map_org_policy(obj, ctx):
    values = obj.values
    name = values.get("name", "")
    key = ctx.key("org_policies", node=values.get("parent"),
                  constraint=name.rsplit("/policies/", 1)[-1],
                  path=f"{obj.address}.name")
    if facts.is_unresolved(key):
        return ()
    spec = _one(values.get("spec"))
    rules = [{"allow_all": rule.get("allow_all"),
              "allowed_values": list(rule.get("allowed_values", [])),
              "condition": rule.get("condition"),
              "denied_values": list(rule.get("denied_values", [])),
              "deny_all": rule.get("deny_all"),
              # the provider spells this STRING boolean "TRUE"; the estate
              # stores the JSON boolean, and normalize.bool_or is the fold.
              "enforce": (normalize.bool_or(rule["enforce"], path="spec.rules.enforce")
                          if "enforce" in rule else None)}
             for rule in spec.get("rules", [])]
    node, constraint = key.split("|")
    record = {"constraint": constraint,
              "inherit_from_parent": normalize.bool_or(spec.get("inherit_from_parent", False),
                                                       path="spec.inherit_from_parent"),
              "node": node,
              "reset": normalize.bool_or(spec.get("reset", False), path="spec.reset"),
              "rules": rules}
    return (facts.Fact(category="org_policies", key=key, record=record,
                       source=obj.source, side=obj.side, origin=obj.artifact,
                       address=obj.address),)


PROJECTIONS = (
    ("google_compute_firewall", _map_firewall, "firewall_rules"),
    ("google_compute_security_policy", _map_armor, "cloud_armor_policies"),
    ("google_compute_security_policy_rule", _map_armor_rule, "cloud_armor_policies"),
    ("google_access_context_manager_service_perimeter", _map_perimeter,
     "vpc_sc_perimeters"),
    ("google_project_iam_binding", _map_iam_binding, "iam_bindings"),
    ("google_project_iam_member", _map_iam_member, "iam_bindings"),
    ("google_org_policy_policy", _map_org_policy, "org_policies"),
)


def _register_projections():
    for resource_type, mapper, category in PROJECTIONS:
        mapping.register(resource_type, mapper, category=category,
                         module="tests.test_gcp_tf_hcl")


def _assemble(result):
    """Category → key → record, joining the FRAGMENTS one estate row is spelled
    across. A Cloud Armor policy's default rule and a project's second IAM
    binding are separate terraform resources; the estate stores one row for
    each, so the fragments concatenate in document order and the rule list
    sorts by the priority that orders it."""
    tables = {}
    for fact in result.facts:
        row = tables.setdefault(fact.category, {}).setdefault(fact.key, {})
        for field, value in fact.record.items():
            if isinstance(value, list) and isinstance(row.get(field), list):
                row[field] = row[field] + value
            else:
                row[field] = value
    for table in tables.values():
        for row in table.values():
            rules = row.get("rules")
            if isinstance(rules, list) and rules and "priority" in rules[0]:
                rules.sort(key=lambda rule: rule["priority"])
    return tables


# -- THE HEADLINE PIN ---------------------------------------------------------


def test_main_tf_maps_onto_the_estate_fixtures_records(estate):
    _register_projections()

    view = hcl.read_file(MAIN_TF, side="current")
    result = mapping.map_objects(view.objects, CTX)
    tables = _assemble(result)

    assert not result.failures, result.failures
    assert not result.skipped, "nothing in main.tf is behind count or for_each"
    for category in PINNED_CATEGORIES:
        built = tables.get(category, {})
        assert sorted(built) == EXPECTED_ROWS[category], (
            f"{category}: main.tf and the estate fixture describe ONE estate, so "
            f"a row that went missing here is a resource this reader lost")
        for key, record in sorted(built.items()):
            stored = estate[category].get(key)
            assert stored is not None, (
                f"{category}: main.tf produced {key!r}, which the estate fixture "
                f"does not store; the two fixtures describe one estate")
            if key == HEALTH_CHECKS:
                continue                # the one stated disagreement, below
            assert record == stored, f"{category}: {key}"


def test_the_health_checks_rule_differs_from_the_estate_in_layer4_alone(estate):
    """The stated fixture disagreement, pinned from BOTH sides.

    ``estate_snapshot.json`` stores an EMPTY ``layer4`` for this rule (an allow
    that matches no packet, which the coverage checks need); ``main.tf`` gives
    it TWO allow blocks (the repeated-block folding fixture). Neither file is
    this reader's to change, so the difference is asserted exactly: ``layer4``
    holds the two folded blocks, and every other attribute is byte-equal.
    """
    _register_projections()

    view = hcl.read_file(MAIN_TF, side="current")
    built = _assemble(mapping.map_objects(view.objects, CTX))["firewall_rules"]

    record = built[HEALTH_CHECKS]
    stored = estate["firewall_rules"][HEALTH_CHECKS]
    assert record["layer4"] == HEALTH_CHECKS_LAYER4
    assert stored["layer4"] == []
    assert record == dict(stored, layer4=HEALTH_CHECKS_LAYER4)


# -- the two stampings --------------------------------------------------------


def test_the_side_selects_the_stamping_and_is_never_inferred():
    current = hcl.read_file(MAIN_TF, side="current")
    proposed = hcl.read_file(MAIN_TF, side="proposed")

    assert [obj.address for obj in current.objects] == \
        [obj.address for obj in proposed.objects], "one parse, two stampings"
    assert {(obj.source, obj.side) for obj in current.objects} == {("hcl", "current")}
    assert {(obj.source, obj.side) for obj in proposed.objects} == \
        {("hcl-proposed", "proposed")}
    assert hcl.PROPOSED_SOURCE in facts.PROPOSED_SOURCES


def test_the_side_argument_is_required_and_closed():
    with pytest.raises(TypeError):
        hcl.read_file(MAIN_TF)                      # no side: nothing is inferred
    with pytest.raises(ValueError, match="explicitly"):
        hcl.read_file(MAIN_TF, side="desired")


# -- the interop rule: repeated blocks fold into a list of objects ------------


def test_two_allow_blocks_fold_into_a_two_element_list():
    objects = _objects(MAIN_TF)

    allow = objects["google_compute_firewall.allow_health_checks"].values["allow"]

    assert allow == [{"protocol": "tcp", "ports": ["80"]},
                     {"protocol": "tcp", "ports": ["443"]}]


def test_a_single_block_is_still_a_one_element_list():
    objects = _objects(MAIN_TF)

    allow = objects["google_compute_firewall.allow_internal"].values["allow"]

    assert allow == [{"protocol": "TCP", "ports": ["0-65535"]}], (
        "a single block is a ONE-ELEMENT list, so a mapper never has to ask "
        "which shape it is holding")


def test_a_block_colliding_with_an_attribute_emits_no_object_and_one_note(tmp_path):
    path = _write(tmp_path, "collide.tf", """
resource "google_compute_firewall" "collide" {
  name    = "collide"
  project = "acme-prod"
  allow   = ["tcp"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
""")

    obj = _objects(path)["google_compute_firewall.collide"]

    assert obj.values["allow"] == ["tcp"], (
        "the attribute's own value stays at its own key; the block emits no "
        "object beside it")
    assert obj.notes == (hcl.COLLISION_NOTE.format(
        address="google_compute_firewall.collide", name="allow"),)


# -- the poison rules, at attribute granularity -------------------------------


def test_a_count_bearing_resource_is_emitted_with_unknown_multiplicity():
    obj = _objects(UNRESOLVABLE_TF)["google_compute_firewall.counted"]

    marker = obj.values["count"]
    assert facts.is_unresolved(marker) and marker.reason == "count"
    assert mapping.multiplicity(obj) is marker, (
        "the reader's own marker is what the multiplicity rule reads")
    assert hcl.MULTIPLICITY_NOTE.format(address=obj.address, meta="count") in obj.notes
    # NOT dropped: the object is still in the census, with its literal siblings.
    assert obj.values["name"] == "counted"


def test_a_count_bearing_resource_contributes_an_unresolved_path():
    triples, unresolved = hcl.parse_config_file(UNRESOLVABLE_TF)

    assert "google_compute_firewall.counted" in [address for address, _t, _v in triples]
    assert "google_compute_firewall.counted.count" in unresolved


def test_a_dynamic_block_appends_exactly_one_marker_to_the_static_blocks():
    obj = _objects(UNRESOLVABLE_TF)["google_compute_security_policy.mixed_rules"]

    rules = obj.values["rule"]
    markers = [item for item in rules if facts.is_unresolved(item)]
    assert len(rules) == 2 and len(markers) == 1, (
        "one static rule block plus ONE appended marker: a dynamic rule block "
        "beside one static rule must not make the body look complete")
    assert rules[0]["action"] == "deny(403)" and rules[0]["priority"] == 1000
    assert markers[0].reason == "dynamic_block"
    assert markers[0].path == "rule[]"


def test_a_dynamic_only_block_is_a_marker_and_nothing_else():
    obj = _objects(UNRESOLVABLE_TF)["google_compute_firewall.fanned_out"]

    allow = obj.values["allow"]
    assert len(allow) == 1 and facts.is_unresolved(allow[0])
    assert allow[0].reason == "dynamic_block" and allow[0].path == "allow[]"


def test_a_dynamic_bearing_resource_contributes_an_unresolved_path():
    triples, unresolved = hcl.parse_config_file(UNRESOLVABLE_TF)

    address = "google_compute_security_policy.mixed_rules"
    assert address in [found for found, _t, _v in triples]
    assert [path for path in unresolved if path.startswith(f"{address}.")] == \
        [f"{address}.rule[1]"]


def test_a_provider_alias_is_noted_and_the_object_is_still_emitted():
    obj = _objects(UNRESOLVABLE_TF)["google_compute_firewall.aliased"]

    assert obj.provider == "google.eu"
    assert obj.values["provider"].reason == "provider_alias"
    assert obj.values["name"] == "aliased", "one poisoned attribute, not a lost object"
    assert hcl.PROVIDER_ALIAS_NOTE.format(address=obj.address,
                                          provider="google.eu") in obj.notes


def test_an_unresolved_attribute_stays_at_its_own_key():
    obj = _objects(UNRESOLVABLE_TF)["google_compute_firewall.mixed_granularity"]

    assert facts.is_unresolved(obj.values["source_ranges"])
    # the siblings are literal and MUST survive: one unresolvable attribute
    # does not poison the two facts the reader actually has.
    assert obj.values["priority"] == 900
    assert obj.values["direction"] == "INGRESS"


# -- never substitute ---------------------------------------------------------


def test_a_variable_default_never_resolves_a_reference_to_it(tmp_path):
    """THE NEVER-SUBSTITUTE PIN. A .tfvars file, a TF_VAR_ environment variable
    or a -var flag each override a default, so the default is one candidate
    among several — substituting it emits a value the run under review may never
    use."""
    path = _write(tmp_path, "vars.tf", """
variable "net_name" {
  type    = string
  default = "vpc-main"
}

resource "google_compute_network" "from_default" {
  name    = var.net_name
  project = "acme-prod"
}
""")

    view = hcl.read_file(path, side="current")
    obj = {found.address: found for found in view.objects}[
        "google_compute_network.from_default"]

    assert facts.is_unresolved(obj.values["name"]), (
        "the declared default may not resolve the reference")
    assert "vpc-main" not in repr(obj.values), "and may not leak in beside it"
    assert hcl.VARIABLE_DEFAULT_NOTE.format(path=str(path), count=1) in view.notes


def test_a_module_block_is_not_followed(tmp_path):
    _write(tmp_path, "root/main.tf", """
module "net" {
  source = "./modules/net"
}

resource "google_compute_network" "root" {
  name    = "vpc-root"
  project = "acme-prod"
}
""")
    _write(tmp_path, "root/modules/net/net.tf", """
resource "google_compute_network" "inside_the_module" {
  name    = "vpc-inside"
  project = "acme-prod"
}
""")

    view = hcl.read_dir(tmp_path / "root", side="current")

    assert view.addresses == ("google_compute_network.root",)
    assert hcl.MODULE_NOTE.format(path=str(tmp_path / "root" / "main.tf"),
                                  name="net") in view.notes


# -- .tf.json: both legal encodings, one answer -------------------------------


def _as_mapping_encoding(resources):
    """The LIST-of-single-key-objects encoding rewritten as the MAPPING one."""
    out = {}
    for element in resources:
        for resource_type, named in element.items():
            if resource_type != "//":
                out.setdefault(resource_type, {}).update(named)
    return out


def _as_list_encoding(resources):
    """The MAPPING encoding rewritten as the LIST-of-single-key-objects one."""
    return [{resource_type: {name: body}}
            for resource_type, named in resources.items()
            for name, body in named.items()]


@pytest.mark.parametrize("fixture", (PERIMETER_JSON, PROPOSAL_JSON),
                         ids=lambda path: path.name)
def test_both_tf_json_encodings_produce_identical_triples(fixture, tmp_path):
    document = json.loads(fixture.read_text(encoding="utf-8"))
    resources = document["resource"]
    if isinstance(resources, list):
        transcoded = dict(document, resource=_as_mapping_encoding(resources))
    else:
        transcoded = dict(document, resource=_as_list_encoding(resources))
    other = _write(tmp_path, "transcoded.tf.json", json.dumps(transcoded))

    original_triples, original_unresolved = hcl.parse_config_file(fixture)
    other_triples, other_unresolved = hcl.parse_config_file(other)

    assert type(document["resource"]) is not type(transcoded["resource"])
    assert original_triples == other_triples
    assert original_unresolved == other_unresolved


def test_a_tf_json_string_carrying_an_interpolation_becomes_unresolved():
    triples, unresolved = hcl.parse_config_file(PERIMETER_JSON)
    values = {address: found for address, _type, found in triples}

    project = values["google_compute_firewall.allow_internal"]["project"]
    assert facts.is_unresolved(project) and project.reason == "interpolation"
    assert unresolved == ("google_compute_firewall.allow_internal.project",)


def test_a_tf_json_block_is_normalised_to_the_list_of_objects_form():
    triples, _unresolved = hcl.parse_config_file(PERIMETER_JSON)
    values = {address: found for address, _type, found in triples}

    status = values["google_access_context_manager_service_perimeter.prod"]["status"]
    assert isinstance(status, list) and len(status) == 1
    assert status[0]["resources"] == ["projects/123456"], (
        "a list of SCALARS is not a block and is left exactly as it is")


# -- the config-directory contract --------------------------------------------


def test_parse_config_dir_does_not_read_a_subdirectory(tmp_path):
    _write(tmp_path, "here/main.tf", """
resource "google_compute_network" "here" {
  name    = "vpc-here"
  project = "acme-prod"
}
""")
    _write(tmp_path, "here/nested/deeper.tf", """
resource "google_compute_network" "deeper" {
  name    = "vpc-deeper"
  project = "acme-prod"
}
""")

    triples, _unresolved = hcl.parse_config_dir(tmp_path / "here")

    assert [address for address, _t, _v in triples] == ["google_compute_network.here"]
    assert hcl.config_files(tmp_path / "here") == (
        str(tmp_path / "here" / "main.tf"),), (
        "terraform does not recurse for a module's own configuration, and "
        "recursing would pull a sibling module's resources into this view")


def test_parse_config_dir_reads_one_directory_in_sorted_order(tmp_path):
    for name in ("z_last.tf", "a_first.tf", "m_middle.tf"):
        _write(tmp_path, f"sorted/{name}", f"""
resource "google_compute_network" "{name.split('.')[0]}" {{
  name    = "vpc-{name.split('.')[0]}"
  project = "acme-prod"
}}
""")

    triples, _unresolved = hcl.parse_config_dir(tmp_path / "sorted")

    assert [address for address, _t, _v in triples] == [
        "google_compute_network.a_first",
        "google_compute_network.m_middle",
        "google_compute_network.z_last"]


def test_one_unreadable_file_costs_that_file_and_not_the_directory(tmp_path):
    _write(tmp_path, "mixed/good.tf", """
resource "google_compute_network" "good" {
  name    = "vpc-good"
  project = "acme-prod"
}
""")
    _write(tmp_path, "mixed/broken.tf", "resource \"google_compute_network\" {\n")

    triples, unresolved = hcl.parse_config_dir(tmp_path / "mixed")

    assert [address for address, _t, _v in triples] == ["google_compute_network.good"]
    assert hcl.UNPARSED_PATH.format(path=str(tmp_path / "mixed" / "broken.tf")) \
        in unresolved


def test_a_directory_of_only_unparsed_files_differs_from_one_with_no_terraform(tmp_path):
    _write(tmp_path, "broken/one.tf", "resource \"google_compute_network\" {\n")
    _write(tmp_path, "broken/two.tf", "resource {{{\n")
    (tmp_path / "empty").mkdir()

    broken = hcl.read_dir(tmp_path / "broken", side="current")
    empty = hcl.read_dir(tmp_path / "empty", side="current")

    assert not broken.ok and not empty.ok
    assert len(broken.unparsed) == 2 and empty.unparsed == ()
    assert hcl.ALL_UNPARSED_NOTE.format(path=str(tmp_path / "broken"), count=2) \
        in broken.notes
    assert hcl.NO_TERRAFORM_NOTE.format(path=str(tmp_path / "empty")) in empty.notes
    assert broken.notes != empty.notes, (
        "a directory whose terraform was all refused is not a directory with no "
        "terraform in it, and nothing may be concluded absent from either")
    broken_triples, broken_unresolved = hcl.parse_config_dir(tmp_path / "broken")
    empty_triples, empty_unresolved = hcl.parse_config_dir(tmp_path / "empty")
    assert broken_triples == empty_triples == ()
    assert len(broken_unresolved) == 2 and empty_unresolved == ()


def test_an_unparsed_file_is_recorded_with_its_note(tmp_path):
    path = _write(tmp_path, "bad.tf", "resource \"google_compute_network\" {\n")

    view = hcl.read_file(path, side="current")

    assert not view.ok and view.objects == ()
    assert [row.path for row in view.unparsed] == [str(path)]
    assert view.unparsed[0].note in view.notes
    assert str(path) in view.unparsed[0].note


# -- the capture time and the desired-state note ------------------------------


def test_the_capture_time_is_the_file_mtime():
    # rendered independently of the module, so this pins the FORMAT too
    expected = datetime.fromtimestamp(os.stat(MAIN_TF).st_mtime,
                                      timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    view = hcl.read_file(MAIN_TF, side="current")

    assert view.captured_at == expected
    assert hcl.MTIME_NOTE.format(path=str(MAIN_TF), stamp=view.captured_at) in view.notes


def test_an_explicit_captured_at_replaces_the_mtime_and_drops_its_note():
    view = hcl.read_file(MAIN_TF, side="current", captured_at="2024-01-01T00:00:00Z")

    assert view.captured_at == "2024-01-01T00:00:00Z"
    assert not [note for note in view.notes if note.startswith(f"{MAIN_TF}: captured_at")], (
        "the mtime note would be false once the caller stamped the capture")


def _every_view(tmp_path):
    """One view of each shape this module returns."""
    _write(tmp_path, "notes/broken.tf", "resource {{{\n")
    (tmp_path / "notes" / "nothing").mkdir(parents=True)
    return (
        hcl.read_file(MAIN_TF, side="current"),
        hcl.read_file(MAIN_TF, side="proposed"),
        hcl.read_file(PERIMETER_JSON, side="current"),
        hcl.read_file(tmp_path / "notes" / "broken.tf", side="current"),
        hcl.read_file(tmp_path / "notes" / "missing.tf", side="current"),
        hcl.read_file(tmp_path / "notes" / "notes.txt", side="current"),
        hcl.read_dir(HCL_DIR, side="current"),
        hcl.read_dir(tmp_path / "notes", side="current"),
        hcl.read_dir(tmp_path / "notes" / "nothing", side="current"),
        hcl.read_dir(tmp_path / "notes" / "absent", side="current"),
    )


def test_the_desired_state_note_is_on_every_view(tmp_path):
    for view in _every_view(tmp_path):
        assert hcl.DESIRED_STATE_NOTE.format(path=view.path) in view.notes, view.path
        assert view.source == hcl.SOURCE_FOR_SIDE[view.side]


def test_a_refused_view_carries_no_objects_and_still_says_why(tmp_path):
    for view in _every_view(tmp_path):
        assert view.notes
        if not view.ok:
            assert view.objects == ()
