"""The one mapper registry, the census, the multiplicity rule — and the value
normalizers the two domain mappers share.

The domain mappers themselves are separate tasks, so every mapper here is a
STUB registered in-test. That is deliberate: what is under test is the seam, not
a domain. The one place a stub would make the test circular is the key, so the
key assertions are anchored twice — at the committed ``main.tf`` on one end and
at the committed ``estate_snapshot.json`` on the other — and the mapping layer
has to land exactly between them.

``terraform`` is not installed on this machine and nothing here needs it: the
fixture objects are built from the committed corpus in the plan-JSON encoding
every reader is required to produce.
"""

import json
import logging
from pathlib import Path

import pytest

from gcp_grounding import facts, identity
from gcp_grounding.tfsource import mapping, normalize

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
MAIN_TF = FIXTURES / "tf" / "hcl" / "main.tf"
UNRESOLVABLE_TF = FIXTURES / "tf" / "hcl" / "unresolvable.tf"
ESTATE = FIXTURES / "estate_snapshot.json"


# -- reading the committed corpus ---------------------------------------------
#
# NOT an HCL reader (that is tfsource/hcl.py's task, and this module must keep
# passing before one exists): just enough to pull ONE resource block's literal
# attributes out of the committed fixture, so these assertions move when the
# fixture moves instead of drifting onto hand-copied constants.

_NOTHING = object()


def _block(text, resource_type, name):
    """The body of one ``resource "<type>" "<name>"`` block."""
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


def _literals(block):
    """The block's own top-level literal attributes; nested blocks are skipped."""
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


@pytest.fixture(scope="module")
def estate():
    return json.loads(ESTATE.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def clean_registry():
    """Registration is import-time and therefore process-global; a stub that
    leaked would answer for every test that ran afterwards.

    The load is forced BEFORE the clear so that whichever test runs first is not
    the one that pays for it: a real domain mapper registers while its module is
    being imported, so a `register` call that happens to trigger that import
    would find the real mapper already holding the type and keep it. Forcing the
    import once and then clearing leaves the seam under test answering with the
    stubs, whether or not a domain mapper module exists in this checkout.
    """
    mapping.mappers()
    mapping.reset_cache()
    yield
    mapping.reset_cache()


class _Collector(logging.Handler):
    """Capture this module's own log records without depending on propagation:
    ``core.log.setup_logging`` turns propagation off, and a warning nobody can
    see is a warning that does not exist."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def warnings_from_mapping():
    logger = logging.getLogger("harness.gcp_grounding.tfsource.mapping")
    collector = _Collector()
    logger.addHandler(collector)
    try:
        yield collector.records
    finally:
        logger.removeHandler(collector)


# -- the stub mappers ---------------------------------------------------------


def _firewall_values():
    """``google_compute_firewall.allow_internal`` from the committed main.tf, in
    the plan-JSON encoding every reader is required to produce: snake_case
    names, repeated blocks as a LIST of objects."""
    block = _block(MAIN_TF.read_text(encoding="utf-8"),
                   "google_compute_firewall", "allow_internal")
    # The nested allow block and the range list are spelled here rather than
    # parsed, so these two lines are pinned against the fixture instead: main.tf
    # writes the protocol in UPPER CASE on purpose (normalize.protocol has to
    # fold it) and the range is the estate's own.
    assert 'protocol = "TCP"' in block and '"0-65535"' in block
    values = dict(_literals(block))
    values["allow"] = [{"protocol": "TCP", "ports": ["0-65535"]}]
    return values


def _firewall_object(**overrides):
    values = dict(_firewall_values())
    values.update(overrides.pop("values", {}))
    return facts.TfObject(
        address="google_compute_firewall.allow_internal",
        type="google_compute_firewall", name="allow_internal",
        source=overrides.pop("source", "hcl-current"),
        side=overrides.pop("side", "current"),
        values=values, artifact=str(MAIN_TF), **overrides)


def _map_firewall(obj, ctx):
    """A stub firewall mapper: it builds its key through the context, exactly as
    a domain mapper must, and its record through :mod:`normalize`."""
    values = obj.values
    key = ctx.key("firewall_rules", name=values.get("name"),
                  project=values.get("project"), path=f"{obj.address}.name")
    if facts.is_unresolved(key):
        return ()
    layer4 = []
    for index, block in enumerate(values.get("allow", ())):
        layer4.append({
            "protocol": normalize.protocol(block.get("protocol"),
                                           path=f"allow[{index}].protocol"),
            "ports": list(normalize.ports(block.get("ports", []),
                                          path=f"allow[{index}].ports")),
        })
    record = {
        "action": "allow" if values.get("allow") else "deny",
        "direction": values.get("direction"),
        "disabled": normalize.bool_or(values.get("disabled", False), path="disabled"),
        "layer4": layer4,
        "network": normalize.strip_self_link(values.get("network"), path="network"),
        "priority": normalize.int_or(values.get("priority", 1000), path="priority"),
        "source_ranges": list(normalize.cidrs(values.get("source_ranges", []),
                                              path="source_ranges")),
    }
    return (facts.Fact(category="firewall_rules", key=key, record=record,
                       source=obj.source, side=obj.side, origin=obj.artifact,
                       address=obj.address),)


def _map_network(obj, ctx):
    key = ctx.key("networks", name=obj.values.get("name"),
                  project=obj.values.get("project"), path=f"{obj.address}.name")
    if facts.is_unresolved(key):
        return ()
    return (facts.Fact(category="networks", key=key, source=obj.source,
                       side=obj.side, address=obj.address),)


def _explodes(obj, ctx):
    raise RuntimeError("this mapper is broken")


def _register_firewall(module="tests.stub_network"):
    return mapping.register("google_compute_firewall", _map_firewall,
                            category="firewall_rules", module=module)


def _object(address, resource_type, **kwargs):
    name = address.split(".")[-1]
    return facts.TfObject(address=address, type=resource_type, name=name,
                          source=kwargs.pop("source", "tfstate"),
                          side=kwargs.pop("side", "current"), **kwargs)


CTX = mapping.MapContext(project="acme-prod", region="us-central1",
                         organization="1", access_policy="987")


# -- the registry -------------------------------------------------------------


def test_a_type_with_no_mapper_lands_in_unrecognized():
    _register_firewall()
    result = mapping.map_objects(
        [_object("google_bigtable_instance.telemetry", "google_bigtable_instance"),
         _firewall_object()], CTX)

    assert [row.type for row in result.unrecognized] == ["google_bigtable_instance"]
    assert result.unrecognized[0].address == "google_bigtable_instance.telemetry"
    assert result.unrecognized[0].reason == "no_mapper"
    assert not result.unmapped
    # the recognized object in the same pass still produced its fact
    assert [fact.category for fact in result.facts] == ["firewall_rules"]


def test_a_deliberate_gap_reads_differently_from_an_oversight():
    unmapped_type = sorted(mapping.DELIBERATELY_UNMAPPED)[0]
    result = mapping.map_objects(
        [_object(f"{unmapped_type}.thing", unmapped_type),
         _object("google_bigtable_instance.telemetry", "google_bigtable_instance")],
        CTX)

    assert [row.type for row in result.unmapped] == [unmapped_type]
    assert result.unmapped[0].reason == "deliberate"
    assert result.unmapped[0].detail == mapping.DELIBERATELY_UNMAPPED[unmapped_type]
    assert [row.type for row in result.unrecognized] == ["google_bigtable_instance"]
    # a STATED gap is not an oversight, so the census counts only the other one
    assert len(result.notes) == 1 and "google_bigtable_instance.telemetry" in result.notes[0]
    assert unmapped_type not in result.notes[0]


def test_a_crashing_mapper_becomes_a_failure_row_and_the_others_still_run():
    _register_firewall()
    mapping.register("google_compute_network", _explodes, category="networks",
                     module="tests.stub_broken")

    result = mapping.map_objects(
        [_object("google_compute_network.vpc_main", "google_compute_network",
                 values={"name": "vpc-main", "project": "acme-prod"}),
         _firewall_object()], CTX)

    assert len(result.failures) == 1
    failure = result.failures[0]
    assert failure.address == "google_compute_network.vpc_main"
    assert failure.type == "google_compute_network"
    assert failure.exception == "RuntimeError"
    assert "this mapper is broken" in failure.detail
    assert failure.module == "tests.stub_broken"
    # crash isolation: the other mapper still ran and the capture is not broken
    assert [fact.category for fact in result.facts] == ["firewall_rules"]


def test_a_mapper_that_returns_junk_is_isolated_the_same_way():
    mapping.register("google_compute_network", lambda obj, ctx: "not a fact",
                     category="networks", module="tests.stub_junk")

    result = mapping.map_objects(
        [_object("google_compute_network.vpc_main", "google_compute_network")], CTX)

    assert not result.facts
    assert [failure.exception for failure in result.failures] == ["TypeError"]


def test_a_duplicate_registration_keeps_the_first_and_warns_naming_both(
        warnings_from_mapping):
    first = _register_firewall(module="tests.stub_network")
    second = mapping.register("google_compute_firewall", _map_network,
                              category="firewall_rules", module="tests.stub_other")

    assert second is first
    assert mapping.mappers()["google_compute_firewall"].map is _map_firewall
    warnings = [record.getMessage() for record in warnings_from_mapping
                if record.levelno >= logging.WARNING]
    assert len(warnings) == 1
    assert "tests.stub_network" in warnings[0] and "tests.stub_other" in warnings[0]
    assert "google_compute_firewall" in warnings[0]


def test_reset_cache_restores():
    _register_firewall()
    assert "google_compute_firewall" in mapping.mappers()

    mapping.reset_cache()

    assert "google_compute_firewall" not in mapping.mappers()
    # and the registry is usable again afterwards
    _register_firewall()
    assert "google_compute_firewall" in mapping.mappers()


def test_a_missing_mapper_module_degrades_to_missing_coverage(monkeypatch):
    """A checkout without one domain mapper loses COVERAGE, not the gate."""
    monkeypatch.setattr(mapping, "MAP_MODULES",
                        ("gcp_grounding.tfsource.no_such_mapper_module",))
    mapping.reset_cache()

    assert dict(mapping.mappers()) == {}

    result = mapping.map_objects([_firewall_object()], CTX)
    assert not result.facts
    assert [row.type for row in result.unrecognized] == ["google_compute_firewall"]


def test_register_refuses_caller_errors():
    with pytest.raises(ValueError, match="not one of"):
        mapping.register("google_x", _map_network, category="permissions")
    with pytest.raises(ValueError, match="DELIBERATELY_UNMAPPED"):
        mapping.register(sorted(mapping.DELIBERATELY_UNMAPPED)[0], _map_network,
                         category="networks")
    with pytest.raises(ValueError, match="callable"):
        mapping.register("google_x", "not callable", category="networks")


def test_the_census_counts_managed_google_resources_and_lists_five():
    objects = [_object(f"google_pubsub_topic.t{index}", "google_pubsub_topic")
               for index in range(7)]
    objects.append(_object("data.google_compute_image.debian",
                           "google_compute_image"))
    objects.append(_object("random_id.suffix", "random_id"))

    result = mapping.map_objects(objects, CTX)

    assert len(result.unrecognized) == 9        # every gap is still recorded
    assert len(result.notes) == 1
    note = result.notes[0]
    assert note.startswith("7 terraform-managed google_* resource(s) have no mapper")
    assert "google_pubsub_topic.t4" in note and "google_pubsub_topic.t5" not in note
    assert "first 5 of 7" in note
    # a data SOURCE is read, not managed; a non-google type is not GCP at all
    assert "data.google_compute_image.debian" not in note
    assert "random_id.suffix" not in note


def test_no_google_resource_with_no_mapper_means_no_census_note():
    _register_firewall()
    assert mapping.map_objects([_firewall_object()], CTX).notes == ()


# -- the multiplicity rule ----------------------------------------------------


def _counted_object(**overrides):
    """``google_compute_firewall.counted`` — the committed count fixture."""
    text = UNRESOLVABLE_TF.read_text(encoding="utf-8")
    assert 'resource "google_compute_firewall" "counted"' in text
    assert "count = var.enabled" in _block(text, "google_compute_firewall", "counted")
    values = dict(_literals(_block(text, "google_compute_firewall", "counted")))
    values["count"] = facts.Unresolved(
        "count", "google_compute_firewall.counted.count", "count = var.enabled ? 1 : 0")
    return facts.TfObject(
        address="google_compute_firewall.counted", type="google_compute_firewall",
        name="counted", source=overrides.pop("source", "hcl-current"),
        side=overrides.pop("side", "current"), values=values,
        artifact=str(UNRESOLVABLE_TF), **overrides)


def test_an_object_behind_count_produces_zero_facts_and_one_skipped_row():
    _register_firewall()

    result = mapping.map_objects([_counted_object(), _firewall_object()], CTX)

    assert len(result.skipped) == 1
    row = result.skipped[0]
    assert row.address == "google_compute_firewall.counted"
    assert row.type == "google_compute_firewall"
    assert row.reason == "count"
    assert row.detail
    # ZERO facts for the resource SET, and the single object beside it is fine
    assert [fact.address for fact in result.facts] == [
        "google_compute_firewall.allow_internal"]
    assert not result.failures and not result.unrecognized


def test_multiplicity_reads_the_meta_argument_the_roll_up_and_the_nested_marker():
    plain = _firewall_object()
    assert mapping.multiplicity(plain) is None

    bare_meta = _firewall_object(values={"count": 3})
    marker = mapping.multiplicity(bare_meta)
    assert marker is not None and marker.reason == "count"
    assert marker.path == "google_compute_firewall.allow_internal.count"

    minted = facts.Unresolved("for_each", "google_compute_firewall.fanned_out.for_each")
    rolled_up = _firewall_object(unresolved=(minted,))
    assert mapping.multiplicity(rolled_up) is minted        # unchanged, with its path

    nested = _firewall_object(values={"allow": [{"protocol": minted}]})
    assert mapping.multiplicity(nested) is minted


def test_a_count_object_is_skipped_before_its_type_is_even_looked_up():
    """The rule is about what the object IS, not about who could map it."""
    result = mapping.map_objects([_counted_object()], CTX)
    assert [row.reason for row in result.skipped] == ["count"]
    assert not result.unrecognized and not result.facts


# -- canonical_from_object: the one translation both sides use ----------------


def test_canonical_from_object_lands_on_the_estate_fixtures_stored_key(estate):
    _register_firewall()
    obj = _firewall_object()
    literals = _literals(_block(MAIN_TF.read_text(encoding="utf-8"),
                                "google_compute_firewall", "allow_internal"))

    category, key, record = mapping.canonical_from_object(obj, CTX)

    assert category == "firewall_rules"
    assert key == identity.canonical_key("firewall_rules", name=literals["name"],
                                         project=literals["project"])
    # the other anchor: that key is the row the estate fixture actually stores
    stored = estate["firewall_rules"][key]
    for attribute in ("action", "direction", "disabled", "layer4", "network",
                      "priority", "source_ranges"):
        assert record[attribute] == stored[attribute], attribute


def test_canonical_from_object_refuses_a_count_bearing_object_on_the_proposed_side():
    _register_firewall()
    proposed = _counted_object(source="hcl-proposed", side="proposed")

    category, key, record = mapping.canonical_from_object(proposed, CTX)

    assert category == "firewall_rules"
    assert facts.is_unresolved(key), "a 0..N resource set has no single identity"
    assert not isinstance(key, str)
    assert key.reason == "count"
    assert record is None


def test_canonical_from_object_says_nothing_about_an_unmapped_type():
    assert mapping.canonical_from_object(
        _object("google_bigtable_instance.t", "google_bigtable_instance"), CTX) is None


def test_canonical_from_object_isolates_a_crashing_mapper_too():
    mapping.register("google_compute_network", _explodes, category="networks",
                     module="tests.stub_broken")

    category, key, record = mapping.canonical_from_object(
        _object("google_compute_network.vpc_main", "google_compute_network"), CTX)

    assert category == "networks"
    assert facts.is_unresolved(key) and record is None


def test_canonical_from_object_is_unresolved_when_the_mapper_had_nothing_to_say():
    _register_firewall()
    nameless = _firewall_object(values={"name": None, "project": None})

    category, key, record = mapping.canonical_from_object(
        nameless, mapping.MapContext())

    assert category == "firewall_rules"
    assert facts.is_unresolved(key) and record is None


# -- MapContext: the qualifiers a bare terraform name cannot supply -----------


def test_the_context_supplies_the_missing_qualifier_and_never_guesses_one():
    with_project = mapping.MapContext(project="acme-prod")
    assert with_project.key("firewall_rules", name="allow-internal") == (
        "projects/acme-prod/global/firewalls/allow-internal")

    nothing = mapping.MapContext()
    key = nothing.key("firewall_rules", name="allow-internal", path="values.name")
    assert facts.is_unresolved(key)
    assert key.reason == "missing_project"
    assert key.path == "values.name"


def test_the_callers_qualifier_wins_over_the_contexts():
    both = mapping.MapContext(project="acme-prod", organization="1")
    # roles accepts project OR organization; a context that knows both must not
    # turn the mapper's explicit project into an ambiguity
    assert both.key("roles", name="ciDeployer", project="acme-prod") == (
        "projects/acme-prod/roles/ciDeployer")
    assert both.key("roles", name="orgAuditor", organization="1") == (
        "organizations/1/roles/orgAuditor")


def test_the_context_resolves_a_project_number_through_its_alias_table():
    ctx = mapping.MapContext(project="acme-prod", project_number="123456")
    assert ctx.alias_table() == {"123456": "acme-prod"}
    assert ctx.key("resource_hierarchy", name="projects/123456") == "projects/acme-prod"
    # a captured alias always wins over the context's own idea of its number
    captured = mapping.MapContext(project="acme-prod", project_number="123456",
                                  aliases={"123456": "acme-staging"})
    assert captured.alias_table()["123456"] == "acme-staging"


def test_the_context_only_offers_parts_the_category_accepts():
    assert CTX.parts_for("network_tags") == {}
    assert CTX.parts_for("subnetworks") == {"project": "acme-prod",
                                            "region": "us-central1"}
    assert CTX.parts_for("vpc_sc_perimeters") == {"access_policy": "987"}
    assert CTX.parts_for("hierarchical_firewall_policies")["parent"] == "organizations/1"


def test_an_unknown_part_name_still_raises_through_the_context():
    with pytest.raises(ValueError, match="unknown key part"):
        CTX.key("networks", name="vpc-main", zone="us-central1-a")


# -- normalize ----------------------------------------------------------------


NORMALIZE_FUNCTIONS = (
    ("strip_self_link", normalize.strip_self_link),
    ("protocol", normalize.protocol),
    ("ports", normalize.ports),
    ("cidrs", normalize.cidrs),
    ("string_list", normalize.string_list),
    ("bool_or", normalize.bool_or),
    ("int_or", normalize.int_or),
    ("project_of", normalize.project_of),
    ("service_account_email", normalize.service_account_email),
    ("principal", normalize.principal),
    ("network_tag", normalize.network_tag),
    ("restricted_service", normalize.restricted_service),
)

SELF_LINK_SPELLINGS = (
    "https://www.googleapis.com/compute/v1/projects/acme-prod/global/networks/vpc-main",
    "https://compute.googleapis.com/compute/v1/projects/acme-prod/global/networks/vpc-main",
    "projects/acme-prod/global/networks/vpc-main",
)

DEGENERATE = (None, "", "   ", [], (), {}, 0, 1, False, True, 3.5, b"bytes",
              "${var.x}", ["${var.x}"], [None], [{}], object())


def test_the_function_table_is_every_public_function():
    exported = {name for name in normalize.__all__
                if callable(getattr(normalize, name))}
    assert exported == {name for name, _ in NORMALIZE_FUNCTIONS}


def test_strip_self_link_agrees_with_identity_on_all_three_spellings():
    """The pin that the delegation was not quietly reimplemented."""
    for spelling in SELF_LINK_SPELLINGS:
        assert (normalize.strip_self_link(spelling, path="values.network")
                == identity.normalize_self_link(spelling))
    stripped = {normalize.strip_self_link(spelling, path="values.network")
                for spelling in SELF_LINK_SPELLINGS}
    assert stripped == {"projects/acme-prod/global/networks/vpc-main"}


@pytest.mark.parametrize("name,function", NORMALIZE_FUNCTIONS)
def test_every_function_passes_an_unresolved_through_unchanged(name, function):
    marker = facts.Unresolved("interpolation", "values.thing", "${var.thing}")
    assert function(marker, path="somewhere.else") is marker


@pytest.mark.parametrize("name,function", NORMALIZE_FUNCTIONS)
def test_no_function_ever_returns_none(name, function):
    for value in DEGENERATE:
        result = function(value, path="values.thing")
        assert result is not None, f"{name}({value!r}) returned None"


@pytest.mark.parametrize("name,function", NORMALIZE_FUNCTIONS)
def test_every_marker_carries_the_path_it_was_threaded(name, function):
    result = function(object(), path="values.thing")
    assert facts.is_unresolved(result)
    assert result.path == "values.thing"


def test_cidrs_is_all_or_nothing():
    good = ["10.0.0.0/8", "35.191.0.0/16"]
    assert normalize.cidrs(good, path="values.source_ranges") == tuple(good)

    result = normalize.cidrs(["10.0.0.0/8", "not-a-range"], path="values.source_ranges")

    assert facts.is_unresolved(result), "one bad member unresolves the WHOLE tuple"
    assert result.reason == "unparsed"
    assert result.path == "values.source_ranges"
    # a marker MEMBER fails the whole list too, and keeps its own minted path
    minted = facts.Unresolved("function_call", "values.source_ranges[1]")
    assert normalize.cidrs(["10.0.0.0/8", minted], path="values.source_ranges") is minted


def test_cidrs_keeps_the_stored_spelling_and_the_armor_any_range():
    assert normalize.cidrs(["0.0.0.0/0"], path="p") == ("0.0.0.0/0",)
    assert normalize.cidrs(["*"], path="p") == ("*",)
    assert normalize.cidrs(["::/0"], path="p") == ("::/0",)


def test_ports_is_all_or_nothing_too():
    assert normalize.ports(["0-65535", "22", 443], path="p") == ("0-65535", "22", "443")
    assert normalize.ports([], path="p") == ()
    for bad in (["22", "70000"], ["22", "90-80"], ["22", "ssh"], ["22", None]):
        assert facts.is_unresolved(normalize.ports(bad, path="p")), bad


def test_protocol_folds_case():
    assert normalize.protocol("TCP", path="allow[0].protocol") == "tcp"
    assert normalize.protocol("tcp", path="allow[0].protocol") == "tcp"
    assert normalize.protocol(6, path="allow[0].protocol") == "6"
    assert facts.is_unresolved(normalize.protocol("t cp", path="allow[0].protocol"))


def test_bool_or_accepts_the_string_forms():
    assert normalize.bool_or("TRUE", path="spec.rules[0].enforce") is True
    assert normalize.bool_or("FALSE", path="spec.rules[0].enforce") is False
    assert normalize.bool_or("true", path="p") is True
    assert normalize.bool_or(False, path="p") is False
    assert normalize.bool_or(True, path="p") is True
    for bad in (1, 0, "yes", "1"):
        assert facts.is_unresolved(normalize.bool_or(bad, path="p")), bad


def test_int_or_reads_both_spellings_and_refuses_a_boolean():
    assert normalize.int_or(1000, path="p") == 1000
    assert normalize.int_or("2147483647", path="p") == 2147483647
    assert normalize.int_or("-1", path="p") == -1
    for bad in (True, False, 3.5, "1e3", ""):
        assert facts.is_unresolved(normalize.int_or(bad, path="p")), bad


def test_string_list_refuses_any_interpolated_member():
    assert normalize.string_list(["web", "bastion"], path="p") == ("web", "bastion")

    result = normalize.string_list(["web", "${var.tier}"], path="values.target_tags")

    assert facts.is_unresolved(result)
    assert result.reason == "interpolation"


def test_project_of_reads_the_three_spellings_and_keeps_a_number_a_number():
    assert normalize.project_of("acme-prod", path="p") == "acme-prod"
    assert normalize.project_of("projects/acme-prod", path="p") == "acme-prod"
    # a project-scoped name carries its own project — reading it out is an
    # extraction, not a guess
    assert normalize.project_of(SELF_LINK_SPELLINGS[0], path="p") == "acme-prod"
    assert normalize.project_of(SELF_LINK_SPELLINGS[2], path="p") == "acme-prod"
    assert normalize.project_of("projects/123456", path="p") == "123456"
    assert facts.is_unresolved(normalize.project_of("organizations/1", path="p"))


def test_service_account_email_agrees_with_the_service_accounts_key():
    email = "ci-deployer@acme-prod.iam.gserviceaccount.com"
    assert normalize.service_account_email(f"serviceAccount:{email}", path="p") == email
    assert normalize.service_account_email(
        f"projects/acme-prod/serviceAccounts/{email}", path="p") == email
    assert normalize.service_account_email(email, path="p") == identity.canonical_key(
        "service_accounts", name=email)
    assert facts.is_unresolved(normalize.service_account_email("ci-deployer", path="p"))


def test_principal_canonicalises_the_prefix_and_never_the_identity():
    assert normalize.principal("serviceAccount:A@acme.example", path="p") == (
        "serviceAccount:A@acme.example")
    assert normalize.principal("serviceaccount:a@acme.example", path="p") == (
        "serviceAccount:a@acme.example")
    assert normalize.principal("allUsers", path="p") == "allUsers"
    assert normalize.principal("deleted:serviceAccount:x@y?uid=1", path="p").startswith(
        "deleted:")
    for bad in ("alice@acme.example", "wizard:alice", "user:"):
        assert facts.is_unresolved(normalize.principal(bad, path="p")), bad


def test_network_tag_and_restricted_service():
    assert normalize.network_tag("Web", path="p") == "Web"     # never case-folded
    assert facts.is_unresolved(normalize.network_tag("a/b", path="p"))
    assert facts.is_unresolved(normalize.network_tag("x" * 64, path="p"))
    assert normalize.restricted_service("Storage.Googleapis.com", path="p") == (
        "storage.googleapis.com")
    assert facts.is_unresolved(normalize.restricted_service("storage", path="p"))
