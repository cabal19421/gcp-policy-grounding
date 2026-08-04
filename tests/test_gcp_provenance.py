"""The one source ledger: fidelity order, scope lattice, the absence predicate
and the sidecar format.

Every assertion here is about a rule that, if it broke, would let the gate
conclude an absence it has not earned: a scope composed to ``complete`` with no
boundary to name what it is complete WITHIN, a category declared complete while
records were demonstrably dropped from it, a terraform artifact claiming to have
enumerated an estate it can only ever partially manage, or an address lookup
handing a check a counterpart from the wrong category.
"""

import difflib
import importlib
import importlib.util
import json
import types
from pathlib import Path

import pytest

from gcp_grounding import facts, provenance, reasoner
from gcp_grounding.knowledge import GcpSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
FULL_SNAPSHOT = FIXTURES / "estate_snapshot.json"
PARTIAL_SNAPSHOT = FIXTURES / "estate_partial_snapshot.json"

# sec_domains registers the estate-tier collections COLLECTION_CATEGORIES maps.
# Branch on the capability with a plain module-level boolean (the suite's
# HAVE_Z3 idiom) rather than skipping, so its absence is asserted to degrade
# honestly instead of quietly deleting the cross-module half of the pin.
HAVE_SEC_DOMAINS = importlib.util.find_spec("gcp_grounding.sec_domains") is not None


@pytest.fixture
def clean_registry():
    """Restore the process-wide soundness registry after a test writes to it."""
    saved = dict(provenance.ESTATE_SOUNDNESS)
    yield
    provenance.ESTATE_SOUNDNESS.clear()
    provenance.ESTATE_SOUNDNESS.update(saved)


# -- the fidelity order -------------------------------------------------------


def test_fidelity_rank_is_strictly_increasing_over_sources():
    ranks = [provenance.fidelity_rank(source) for source in provenance.SOURCES]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)
    assert all(b - a == 1 for a, b in zip(ranks, ranks[1:]))

    # The two positions the whole order exists for: a fixture must lose to
    # everything, a human-typed baseline must win over everything, and an
    # undeclared snapshot must not outrank a capture that declared itself.
    assert provenance.SOURCES[0] == "fixture"
    assert provenance.SOURCES[-1] == "explicit-baseline"
    assert (provenance.fidelity_rank("unattributed")
            < provenance.fidelity_rank("api")
            < provenance.fidelity_rank("explicit-baseline"))
    assert provenance.fidelity_rank("hcl") < provenance.fidelity_rank("tfstate")


def test_fidelity_rank_raises_on_unknown_and_on_every_proposed_spelling():
    with pytest.raises(ValueError, match="unknown source"):
        provenance.fidelity_rank("tfstate-ish")

    # A proposed fact never participates in a winner selection, so ranking one
    # against reality is not a meaningful question.
    for spelling in facts.PROPOSED_SOURCES:
        assert spelling not in provenance.SOURCES
        with pytest.raises(ValueError, match="PROPOSED"):
            provenance.fidelity_rank(spelling)


# -- the scope lattice --------------------------------------------------------


def test_compose_scope_is_commutative_and_associative_over_the_lattice():
    """Exhaustive over SCOPES: order-independence is what makes a merge safe."""
    for boundary in ("", "organizations/1"):
        for a in provenance.SCOPES:
            for b in provenance.SCOPES:
                left = provenance.compose_scope((a, boundary), (b, boundary))
                right = provenance.compose_scope((b, boundary), (a, boundary))
                assert left == right
                for c in provenance.SCOPES:
                    # Composition returns a (scope, boundary) pair precisely so
                    # the next composition can re-check it.
                    nested_left = provenance.compose_scope(
                        provenance.compose_scope((a, boundary), (b, boundary)),
                        (c, boundary))
                    nested_right = provenance.compose_scope(
                        (a, boundary),
                        provenance.compose_scope((b, boundary), (c, boundary)))
                    flat = provenance.compose_scope((a, boundary), (b, boundary),
                                                    (c, boundary))
                    assert nested_left == nested_right == flat


def test_compose_scope_is_commutative_across_differing_boundaries():
    pairs = [(scope, boundary)
             for scope in provenance.SCOPES
             for boundary in ("", "organizations/1", "organizations/2")]
    for left in pairs:
        for right in pairs:
            assert (provenance.compose_scope(left, right)
                    == provenance.compose_scope(right, left))


def test_compose_scope_is_the_lattice_max():
    assert provenance.compose_scope("uncaptured", "undeclared")[0] == "undeclared"
    assert provenance.compose_scope("undeclared", "partial")[0] == "partial"
    assert provenance.compose_scope("partial", "complete")[0] == "complete"
    assert provenance.compose_scope() == ("uncaptured", "")


def test_two_differing_boundaries_cap_at_partial_and_two_identical_ones_do_not():
    same = provenance.compose_scope(("complete", "organizations/1"),
                                    ("complete", "organizations/1"))
    assert same == ("complete", "organizations/1")

    differing = provenance.compose_scope(("complete", "organizations/1"),
                                         ("complete", "organizations/2"))
    assert differing == ("partial", "")


def test_the_empty_versus_named_boundary_case_also_caps_at_partial():
    """The case that under-fires if it is left out.

    A boundary-less terraform source composed with an API capture complete
    within one organization would otherwise yield ``complete`` with no boundary
    at all, licensing an estate-wide negative over merged content that includes
    projects outside that organization.
    """
    composed = provenance.compose_scope(("complete", ""),
                                        ("complete", "organizations/1"))
    assert composed == ("partial", "")


def test_an_uncaptured_boundaryless_contributor_does_not_cap_the_composition():
    """It contributes no content, so it describes no boundary."""
    composed = provenance.compose_scope(("uncaptured", ""),
                                        ("complete", "organizations/1"))
    assert composed == ("complete", "organizations/1")


def test_the_composed_boundary_is_the_shared_string_or_empty():
    assert provenance.compose_scope(("partial", "folders/9"),
                                    ("complete", "folders/9")) == ("complete", "folders/9")
    assert provenance.compose_scope(("partial", "folders/9"),
                                    ("partial", "folders/8"))[1] == ""


def test_taints_compose_so_a_later_one_wins():
    assert provenance.compose_taint("", "disputed") == "disputed"
    assert provenance.compose_taint("stale", "disputed") == "stale"
    assert provenance.compose_taint("stale", "unmergeable") == "unmergeable"
    with pytest.raises(ValueError, match="unknown taint"):
        provenance.compose_taint("suspicious")


# -- the structural coercions -------------------------------------------------


def test_a_terraform_source_record_claiming_complete_is_coerced_to_partial():
    record = provenance.SourceRecord("state", "tfstate", origin="terraform.tfstate",
                                     scope="complete")
    assert record.scope == "partial"
    assert "coerced" in record.note and "partial" in record.note

    # Coerce, never raise: a buggy reader may neither lie about coverage nor
    # crash the gate.
    for kind in provenance.TERRAFORM_SOURCES:
        assert provenance.SourceRecord("s", kind, scope="complete").scope == "partial"
    assert provenance.SourceRecord("s", "api", scope="complete").scope == "complete"


def test_a_terraform_category_scope_is_coerced_the_same_way():
    scope = provenance.CategoryScope(scope="complete", source_kinds=("api", "tfstate"))
    assert scope.scope == "partial"
    assert "terraform" in scope.note


def test_a_category_with_drops_is_demoted_and_require_complete_names_them():
    scope = provenance.CategoryScope(scope="complete", keys=4, dropped=2,
                                     reasons=("unknown_after_apply", "interpolation"),
                                     source_kinds=("api",))
    assert scope.scope == "partial"
    assert "dropped" in scope.note
    assert scope.reasons == ("interpolation", "unknown_after_apply")   # sorted, distinct
    assert scope.existence_licensed is False

    ledger = provenance.SourceLedger(categories={"firewall_rules": scope})
    reason = provenance.require_complete(ledger, "firewall_rules", rule="SEC-3")
    assert reason == (
        "rule 'SEC-3' reasons from absence, but category 'firewall_rules' dropped "
        "2 record(s) (interpolation, unknown_after_apply) - a category with known "
        "holes cannot license a negative")
    assert reason.isascii()


def test_nothing_emitted_implies_no_keys_and_an_uncaptured_scope():
    scope = provenance.CategoryScope(scope="complete", keys=7, emitted=False)
    assert (scope.scope, scope.keys) == ("uncaptured", 0)
    assert "uncaptured" in scope.note
    assert provenance.UNCAPTURED.scope == "uncaptured"


def test_serial_and_lineage_are_legal_only_for_a_tfstate_source():
    state = provenance.SourceRecord("s", "tfstate", serial=7, lineage="abc-def")
    assert (state.serial, state.lineage) == (7, "abc-def")

    for kind in ("hcl", "tfplan-prior", "api", "explicit-baseline"):
        with pytest.raises(ValueError, match="serial"):
            provenance.SourceRecord("s", kind, serial=7)
        with pytest.raises(ValueError, match="lineage"):
            provenance.SourceRecord("s", kind, lineage="abc-def")


def test_an_unknown_source_kind_or_scope_is_refused():
    with pytest.raises(ValueError, match="not one of"):
        provenance.SourceRecord("s", "guess")
    with pytest.raises(ValueError, match="unknown scope"):
        provenance.CategoryScope(scope="mostly")


# -- require_complete against the committed fixtures --------------------------


def test_require_complete_on_the_committed_estate_fixture():
    """A snapshot stamped complete licenses absence in what it captured, and in
    nothing else. Both strings are pinned as literals: they are embedded in
    verdict messages that get compared, grepped and diffed."""
    snapshot = GcpSnapshot.load(FULL_SNAPSHOT)
    ledger = provenance.SourceLedger.unattributed(snapshot, scope="complete")

    assert provenance.require_complete(ledger, "roles") is None
    assert provenance.require_complete(snapshot, "roles") is None

    # The committed full fixture carries all eighteen categories, so the
    # uncaptured arm is pinned against the committed PARTIAL fixture, whose
    # record tables were deliberately never captured.
    partial = GcpSnapshot.load(PARTIAL_SNAPSHOT)
    assert partial.firewall_rules is None
    expected = ("this check reasons from absence, but category 'firewall_rules' was "
                "not captured - an uncaptured category cannot be read as an empty one")
    assert provenance.require_complete(
        provenance.SourceLedger.unattributed(partial), "firewall_rules") == expected
    # A plain GcpSnapshot reproduces today's semantics exactly, so adoption is
    # incremental.
    assert provenance.require_complete(partial, "firewall_rules") == expected
    assert expected.isascii()


def test_require_complete_names_the_taint_and_the_scope():
    ledger = provenance.SourceLedger(categories={
        "roles": provenance.CategoryScope(scope="complete", taint="disputed",
                                          source_kinds=("api",)),
        "networks": provenance.CategoryScope(scope="partial", boundary="organizations/1",
                                             source_kinds=("tfstate",)),
    })
    assert provenance.require_complete(ledger, "roles") == (
        "this check reasons from absence, but category 'roles' is tainted 'disputed' "
        "- a disputed category cannot license a negative")
    assert provenance.require_complete(ledger, "networks", rule="SEC-9") == (
        "rule 'SEC-9' reasons from absence, but category 'networks' has partial "
        "coverage from tfstate within 'organizations/1' - absence within a partial "
        "capture is not absence")
    assert provenance.require_complete(ledger, "org_policies").endswith(
        "an uncaptured category cannot be read as an empty one")


def test_scope_verdict_wraps_the_predicate_without_a_new_status():
    snapshot = GcpSnapshot.load(PARTIAL_SNAPSHOT)
    verdict = provenance.scope_verdict(snapshot, "firewall_rules", rule="SEC-1")
    assert verdict.status == "unverified"
    assert verdict.kind == "scope"
    assert verdict.target == "firewall_rules"
    assert "was not captured" in verdict.message
    assert provenance.scope_verdict(snapshot, "roles") is None


def test_the_read_api_is_total_and_never_raises():
    empty = provenance.SourceLedger()
    assert empty.scope_of("roles") is provenance.UNCAPTURED
    assert empty.origin_of("roles", "roles/nope") is None
    assert empty.by_locator("google_compute_firewall.nope") == set()
    assert empty.taint_of("roles", "roles/nope") == ""
    assert empty.tainted_categories() == ()
    assert empty.merged_captured_at() == ""
    assert empty.alternates_for("roles", "roles/nope") == ()
    assert provenance.require_complete(None, "roles") is not None


# -- one address is many facts ------------------------------------------------


def _firewall_ledger():
    """One address emitting a firewall fact plus two network_tags side facts."""
    builder = provenance.LedgerBuilder()
    builder.source("state", "tfstate", origin="terraform.tfstate",
                   captured_at="2026-07-01T00:00:00Z", scope="partial")
    builder.declare("firewall_rules", scope="partial", source_kinds=("tfstate",))
    builder.declare("network_tags", scope="partial", source_kinds=("tfstate",))
    address = "google_compute_firewall.allow_ssh"
    builder.fact("firewall_rules", "projects/acme-prod/global/firewalls/allow-ssh",
                 source_id="state", locator=address)
    for tag in ("web", "bastion"):
        builder.fact("network_tags", tag, source_id="state", locator=address)
    return builder.build(), address


def test_by_locator_is_multi_valued_and_category_scoped():
    """A single address legitimately produces several facts in several
    categories, so a single-valued lookup would hand a firewall check a
    network_tags fact as its baseline — the wrong-counterpart failure arriving
    through the ambiguity guard's blind spot."""
    ledger, address = _firewall_ledger()

    assert len(ledger.by_locator(address)) == 3
    assert ledger.by_locator(address, category="firewall_rules") == {
        ("firewall_rules", "projects/acme-prod/global/firewalls/allow-ssh")}
    assert len(ledger.by_locator(address, category="network_tags")) == 2
    assert ledger.by_locator(address, category="roles") == set()


def test_two_sources_on_one_address_in_one_category_is_the_ambiguity_case():
    builder = provenance.LedgerBuilder()
    builder.source("prod", "tfstate", scope="partial")
    builder.source("dev", "tfstate", scope="partial")
    builder.declare("firewall_rules", scope="partial", source_kinds=("tfstate",))
    address = "google_compute_firewall.allow_ssh"
    builder.fact("firewall_rules", "projects/acme-prod/global/firewalls/allow-ssh",
                 source_id="prod", locator=address)
    builder.fact("firewall_rules", "projects/acme-dev/global/firewalls/allow-ssh",
                 source_id="dev", locator=address)
    ledger = builder.build()

    hits = ledger.by_locator(address, category="firewall_rules")
    assert len(hits) == 2          # the caller's baseline:ambiguous case


def test_taint_falls_back_from_the_fact_to_the_category():
    builder = provenance.LedgerBuilder()
    builder.source("state", "tfstate", scope="partial")
    builder.declare("network_tags", scope="partial", taint="stale",
                    source_kinds=("tfstate",))
    builder.fact("network_tags", "web", source_id="state", locator="a.b",
                 taint="disputed")
    builder.fact("network_tags", "bastion", source_id="state", locator="a.b")
    ledger = builder.build()

    assert ledger.taint_of("network_tags", "web") == "disputed"      # the fact's
    assert ledger.taint_of("network_tags", "bastion") == "stale"     # the category's
    assert ledger.taint_of("network_tags", "absent") == "stale"
    assert ledger.tainted_categories() == ("network_tags",)


def test_merged_captured_at_is_the_oldest_constituent():
    builder = provenance.LedgerBuilder()
    builder.source("old", "tfstate", captured_at="2026-01-01T00:00:00Z", scope="partial")
    builder.source("new", "api", captured_at="2026-07-18T09:30:00Z", scope="complete")
    assert builder.build().merged_captured_at() == "2026-01-01T00:00:00Z"


# -- the builder --------------------------------------------------------------


def test_builder_fact_on_an_undeclared_category_raises():
    builder = provenance.LedgerBuilder()
    builder.source("state", "tfstate", scope="partial")
    with pytest.raises(ValueError, match="never declared"):
        builder.fact("firewall_rules", "projects/p/global/firewalls/a",
                     source_id="state", locator="google_compute_firewall.a")

    builder.declare("firewall_rules", scope="partial", source_kinds=("tfstate",))
    with pytest.raises(ValueError, match="never added"):
        builder.fact("firewall_rules", "projects/p/global/firewalls/a",
                     source_id="ghost", locator="google_compute_firewall.a")


def test_builder_counts_keys_drops_and_the_census():
    builder = provenance.LedgerBuilder()
    builder.source("state", "tfstate", scope="partial")
    builder.declare("firewall_rules", scope="partial", source_kinds=("tfstate",))
    builder.fact("firewall_rules", "projects/p/global/firewalls/a", source_id="state")
    builder.drop("firewall_rules", count=2, reasons=("interpolation", "interpolation"))
    builder.saw_unmapped("google_project_service")
    builder.saw_unmapped("google_something_new")
    ledger = builder.build()

    scope = ledger.scope_of("firewall_rules")
    assert (scope.keys, scope.dropped, scope.reasons) == (1, 2, ("interpolation",))
    assert ledger.census.unmapped == {"google_project_service": 1}
    assert ledger.census.unrecognized == {"google_something_new": 1}
    assert "google_project_service" in provenance.DELIBERATELY_UNMAPPED


def test_unattributed_takes_the_scope_as_a_parameter():
    snapshot = GcpSnapshot.load(FULL_SNAPSHOT)
    default = provenance.SourceLedger.unattributed(snapshot)
    assert default.scope_of("roles").scope == "complete"       # the legacy API path
    assert default.declared_categories() == snapshot.captured_categories()
    assert default.scope_of("roles").keys == len(snapshot.roles)

    declared = provenance.SourceLedger.unattributed(snapshot, scope="undeclared")
    assert declared.scope_of("roles").scope == "undeclared"
    assert provenance.require_complete(declared, "roles") is not None


# -- persistence --------------------------------------------------------------


def test_from_dict_rejects_an_unknown_key_nested_in_a_category_scope():
    ledger, _ = _firewall_ledger()
    data = ledger.to_dict()
    data["categories"]["firewall_rules"]["complete_ish"] = True

    with pytest.raises(ValueError) as excinfo:
        provenance.SourceLedger.from_dict(data)
    message = str(excinfo.value)
    assert "complete_ish" in message and "firewall_rules" in message


def test_a_wrong_schema_id_names_both_strings():
    ledger, _ = _firewall_ledger()
    data = ledger.to_dict()
    data["schema"] = "gcp-source-ledger/2"

    with pytest.raises(ValueError) as excinfo:
        provenance.SourceLedger.from_dict(data)
    message = str(excinfo.value)
    assert "gcp-source-ledger/1" in message and "gcp-source-ledger/2" in message


def test_a_round_trip_is_byte_stable(tmp_path):
    ledger, _ = _firewall_ledger()
    path = tmp_path / "estate.origins.json"
    ledger.write(path)
    first = path.read_text(encoding="utf-8")

    provenance.SourceLedger.load(path).write(path)
    assert path.read_text(encoding="utf-8") == first
    assert provenance.SourceLedger.load(path).to_dict() == ledger.to_dict()


def test_load_raises_naming_the_path(tmp_path):
    path = tmp_path / "estate.origins.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match=str(path)):
        provenance.SourceLedger.load(path)


def test_write_is_atomic(tmp_path, monkeypatch):
    """A crashed capture must never leave a half-written sidecar: the previous
    ledger is still the one on disk, byte for byte."""
    path = tmp_path / "estate.origins.json"
    ledger, _ = _firewall_ledger()
    ledger.write(path)
    original = path.read_text(encoding="utf-8")

    def boom(*args, **kwargs):
        raise RuntimeError("serializer died mid-way")

    monkeypatch.setattr(provenance.json, "dump", boom)
    with pytest.raises(RuntimeError, match="mid-way"):
        provenance.SourceLedger().write(path)

    assert path.read_text(encoding="utf-8") == original
    assert [p.name for p in tmp_path.iterdir()] == [path.name]   # no temp left behind


def _with_extra_category(builder_categories):
    builder = provenance.LedgerBuilder()
    builder.source("api", "api", origin="cloudasset.assets.list",
                   captured_at="2026-07-18T09:30:00Z", scope="complete")
    for category in builder_categories:
        builder.declare(category, scope="complete", source_kinds=("api",))
    return builder.build()


def test_a_written_sidecar_is_multiline_key_sorted_and_newline_terminated(tmp_path):
    ledger, _ = _firewall_ledger()
    path = tmp_path / "estate.origins.json"
    ledger.write(path)
    text = path.read_text(encoding="utf-8")

    assert text.count("\n") > 20                      # multi-line, not one blob
    assert text.endswith("}\n") and not text.endswith("\n\n")
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"


def test_adding_one_category_changes_exactly_that_category_s_lines(tmp_path):
    """CI reviews drift BY DIFF, so the format is part of the contract."""
    before = tmp_path / "before.origins.json"
    after = tmp_path / "after.origins.json"
    _with_extra_category(("networks", "subnetworks")).write(before)
    _with_extra_category(("networks", "roles", "subnetworks")).write(after)

    old = before.read_text(encoding="utf-8").splitlines()
    new = after.read_text(encoding="utf-8").splitlines()
    matcher = difflib.SequenceMatcher(None, old, new)
    changed = []
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        assert tag in ("equal", "insert"), f"{tag} — a category changed other lines"
        if tag == "insert":
            changed.extend(new[j1:j2])

    assert changed, "adding a category must change something"
    joined = "\n".join(changed)
    assert '"roles"' in joined
    assert "networks" not in joined and "subnetworks" not in joined


def test_origins_path_is_the_single_definition_of_where_the_sidecar_lives():
    assert provenance.origins_path("estate_snapshot.json") == "estate_snapshot.origins.json"
    assert provenance.origins_path("/a/b/estate_snapshot") == "/a/b/estate_snapshot.origins.json"
    assert provenance.origins_path("/a/b/estate.snapshot") == "/a/b/estate.snapshot.origins.json"
    assert provenance.origins_path(Path("/a/b/estate_snapshot.json")) == \
        "/a/b/estate_snapshot.origins.json"


# -- the coverage summary -----------------------------------------------------


def test_summarize_has_one_line_per_declared_category_and_the_census():
    ledger, _ = _firewall_ledger()
    rendered = provenance.summarize(ledger)
    lines = rendered.splitlines()

    for category in ledger.declared_categories():
        matching = [line for line in lines if line.strip().startswith(category)]
        assert len(matching) == 1, f"{category} should have exactly one line"
        assert "partial" in matching[0]
    assert "unrecognized terraform types" in rendered
    assert "deliberately unmapped types" in rendered
    assert provenance.SCHEMA in rendered


def test_summarize_says_so_when_nothing_was_declared():
    rendered = provenance.summarize(provenance.SourceLedger())
    assert "no category was declared" in rendered


# -- the two soundness registries ---------------------------------------------


def test_estate_soundness_defaults_to_requires_complete(clean_registry):
    assert provenance.estate_soundness("gcp_grounding.fw_checks.check_nothing") == \
        "requires_complete"
    assert provenance.DEFAULT_SOUNDNESS == "requires_complete"

    identity = "gcp_grounding.fw_checks.check_open_ssh"
    provenance.register_estate_soundness(identity, "subset_safe", "firewall_rules")
    assert provenance.estate_soundness(identity) == "subset_safe"
    assert provenance.ESTATE_SOUNDNESS[identity] == "subset_safe"
    assert provenance.estate_soundness_category(identity) == "firewall_rules"

    provenance.register_estate_soundness(identity, "requires_complete")
    assert provenance.estate_soundness(identity) == "requires_complete"
    assert provenance.estate_soundness_category(identity) is None

    with pytest.raises(ValueError, match="soundness mode"):
        provenance.register_estate_soundness(identity, "probably_fine")


def test_collection_categories_map_to_real_snapshot_categories():
    # CATEGORIES is derived from the snapshot model, never restated, so a new
    # estate category cannot be forgotten here.
    assert provenance.CATEGORIES == GcpSnapshot.load(FULL_SNAPSHOT).captured_categories()
    for collection, category in provenance.COLLECTION_CATEGORIES.items():
        assert category in provenance.CATEGORIES, collection
    assert provenance.COLLECTION_CATEGORIES["firewall_rules"] == "firewall_rules"
    assert provenance.COLLECTION_CATEGORIES["hier_firewall_rules"] == \
        "hierarchical_firewall_policies"

    if HAVE_SEC_DOMAINS:
        sec_domains = importlib.import_module("gcp_grounding.sec_domains")
        estate = [spec.name for spec in sec_domains.COLLECTION_SPECS
                  if spec.tier == "estate"]
        assert estate, "sec_domains registers at least one estate collection"
        for name in estate:
            assert name in provenance.COLLECTION_CATEGORIES
    else:
        # sec_domains has not landed here; assert the half that IS decidable —
        # every mapped name is spelled like a collection and resolves.
        for collection in provenance.COLLECTION_CATEGORIES:
            assert collection and collection == collection.lower()


def test_verdict_kind_categories_covers_every_existence_verdict():
    """``ground_existence`` emits the verdict kind in the singular and the
    snapshot names its categories in the plural; this map is the bridge, which
    is what makes a kind-to-category post-pass possible."""
    for category in provenance.VERDICT_KIND_CATEGORIES.values():
        assert category in provenance.CATEGORIES

    snapshot = GcpSnapshot.load(FULL_SNAPSHOT)
    claims = [types.SimpleNamespace(kind=kind, value="no-such-thing",
                                    location=f"$.{kind}")
              for kind in reasoner.EXISTENCE_KINDS]
    report = reasoner.ground_existence(claims, snapshot)

    assert len(report.verdicts) == len(reasoner.EXISTENCE_KINDS)
    for verdict in report.verdicts:
        assert verdict.kind in provenance.VERDICT_KIND_CATEGORIES
        category = provenance.VERDICT_KIND_CATEGORIES[verdict.kind]
        assert getattr(snapshot, category) is not None
