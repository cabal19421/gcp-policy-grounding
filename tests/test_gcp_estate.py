"""``estate.py``: resolutions in, a ``GcpSnapshot`` plus a ``SourceLedger`` out.

THE HEADLINE PIN is the pair below it: capturing ``tests/fixtures/gcp/tf/``
produces ``firewall_rules``, ``iam_bindings`` and ``org_policies`` records EQUAL
to the loaded ``tests/fixtures/gcp/estate_snapshot.json``'s, and the
BOTH-DIRECTIONS fixture-consistency pin this task owns for that tree.

Why both directions. "Equal for every key both hold" is VACUOUSLY TRUE under a
key-form regression that makes every produced key miss the table: the
intersection is empty, the loop body never runs, and the run reports zero
mismatches. That is exactly the failure ``baseline:key-mismatch`` and merge's
``drift:key-mismatch`` exist to catch at runtime, and it must not be allowed to
pass here at fixture time. So every canonical key the tree produces is either in
the estate fixture or listed in :data:`DELIBERATELY_EXTRA` with a reason, and
every key the fixture holds for an emitted category is either produced or listed
in :data:`DELIBERATELY_ABSENT` with a reason.

``terraform`` is not installed on this machine and nothing here needs it. The
committed corpus supplies every positive fixture; degenerate inputs are written
into ``tmp_path`` per the suite convention.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from gcp_grounding import estate, facts, merge, provenance, redact
from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot
from gcp_grounding.provenance import SourceRecord
from gcp_grounding.tfsource import state as tfstate_reader

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
TF_DIR = FIXTURES / "tf"
STATE_PATH = TF_DIR / "estate.tfstate"
ESTATE_PATH = FIXTURES / "estate_snapshot.json"

#: The qualifiers a bare terraform name cannot supply. They come from the
#: artifact's workspace, never from the resource; the committed tree describes
#: project acme-prod (number 123456) under organization 1 and access policy 987.
QUALIFIERS = dict(project="acme-prod", project_number="123456",
                  organization="1", access_policy="987")

#: A pinned stamp for every determinism assertion. Without it the capture falls
#: back to the artifacts' mtimes, which are whenever the checkout happened.
PINNED = "2026-07-18T09:30:00Z"

#: The three record tables the design names for the equality pin.
RECORD_PINS = ("firewall_rules", "iam_bindings", "org_policies")

#: Every canonical key the committed tree produces that the estate fixture does
#: NOT store, with the reason it is there. All of them come from the two
#: fixtures that exist to be unresolvable or to be a proposal.
DELIBERATELY_EXTRA = {
    "cloud_armor_policies": {
        "projects/acme-prod/global/securityPolicies/mixed-rules":
            "unresolvable.tf's silent-truncation fixture: one static rule beside "
            "a dynamic one. The dynamic block takes the whole rule list with it, "
            "so the record is dropped whole rather than reported one rule short, "
            "and the estate never stores a policy that does not exist",
    },
    "firewall_rules": {
        "projects/acme-prod/global/firewalls/aliased":
            "unresolvable.tf's provider-alias fixture: the rule exists only to "
            "prove an aliased provider is NOTED rather than resolved, and the "
            "object is still emitted with its literal siblings intact",
        "projects/acme-prod/global/firewalls/bare-network":
            "unresolvable.tf's missing-project fixture: a bare 'default' network "
            "with no project attribute, keyed here only because the capture was "
            "handed the workspace project explicitly",
        "projects/acme-prod/global/firewalls/local-reference":
            "unresolvable.tf's local-value fixture; its network is an "
            "interpolation, so drop_unresolved drops the record whole",
        "projects/acme-prod/global/firewalls/mixed-granularity":
            "unresolvable.tf's attribute-granularity fixture; source_ranges is "
            "an interpolation, so the record is dropped whole even though "
            "priority and direction are literal",
        "projects/acme-prod/global/firewalls/resource-reference":
            "unresolvable.tf's resource-reference fixture; the network is "
            "another resource's apply-time id",
        "projects/acme-prod/global/firewalls/splat-reference":
            "unresolvable.tf's splat fixture; source_tags expands over instances "
            "that exist only after apply",
        "projects/acme-prod/global/firewalls/allow-ssh-world":
            "proposal.tf.json is the gate's reviewable HCL-JSON PROPOSAL fixture. "
            "A whole-tree capture reads every configuration file in the tree as "
            "DESIRED state, so the rule under review turns up as a "
            "terraform-declared extra; the fidelity order is what keeps it from "
            "outranking anything real",
    },
}

#: Every key the estate fixture holds for an EMITTED category that the tree does
#: not produce, with the reason.
DELIBERATELY_ABSENT = {
    "network_tags": {
        "bastion":
            "no artifact in the tree names it. It is in the estate to prove the "
            "tag vocabulary is wider than terraform's view of it, which is why "
            "network_tags is presence-only and may never answer False",
        "db":
            "named only by estate_plan.json's planned_values and change.after - "
            "the PROPOSED side - so it never reaches a current-state fact",
    },
}

#: One resolvable rule and one whose source_ranges is an interpolation, so the
#: capture has exactly one survivor and exactly one drop in one category.
ONE_HOLE_TF = """
variable "cidr" {
  type = string
}

resource "google_compute_firewall" "solid" {
  name          = "solid"
  project       = "acme-prod"
  network       = "projects/acme-prod/global/networks/vpc-main"
  direction     = "INGRESS"
  source_ranges = ["10.0.0.0/8"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "holed" {
  name          = "holed"
  project       = "acme-prod"
  network       = "projects/acme-prod/global/networks/vpc-main"
  direction     = "INGRESS"
  source_ranges = ["${var.cidr}"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
"""

PLAIN_TF = """
resource "google_compute_firewall" "plain" {
  name          = "plain"
  project       = "acme-prod"
  network       = "projects/acme-prod/global/networks/vpc-main"
  direction     = "INGRESS"
  source_ranges = ["10.0.0.0/8"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
"""


def _options(**overrides):
    merged = dict(QUALIFIERS)
    merged.update(overrides)
    return estate.CaptureOptions(**merged)


@pytest.fixture(scope="module")
def tree():
    """The committed tree, captured once with the artifacts' own mtimes."""
    return estate.capture(TF_DIR, options=_options())


@pytest.fixture(scope="module")
def everything():
    """The same tree with every EXISTENCE_LICENSING category opted in, so the
    both-directions pin can see every canonical key the tree produces rather
    than only the four DEFAULT_EMIT tables."""
    return estate.capture(TF_DIR, options=_options(
        include=estate.EXISTENCE_LICENSING, captured_at=PINNED))


@pytest.fixture(scope="module")
def fixture_estate():
    return GcpSnapshot.load(ESTATE_PATH)


def _produced(capture):
    """Category -> every canonical key the capture RESOLVED, survivors and
    dropped records alike. A dropped record still proves the key form."""
    out = {}
    for category in capture.snapshot.captured_categories():
        out[category] = set(getattr(capture.snapshot, category))
    for row in capture.dropped:
        out.setdefault(row.category, set()).add(row.key)
    return out


def _write(tmp_path, name, text):
    target = Path(tmp_path) / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


# -- the emit policy ----------------------------------------------------------


def test_the_emit_policy_partitions_the_terraform_categories():
    assert estate.DEFAULT_EMIT == ("firewall_rules", "iam_bindings",
                                   "org_policies", "network_tags")
    assert set(estate.DEFAULT_EMIT) <= set(facts.TF_CATEGORIES)
    assert set(estate.DEFAULT_EMIT).isdisjoint(estate.EXISTENCE_LICENSING)
    assert set(estate.DEFAULT_EMIT) | set(estate.EXISTENCE_LICENSING) == \
        set(facts.TF_CATEGORIES)


def test_an_existence_licensing_category_is_opt_in_only(tree):
    # networks is a real terraform category the reasoner READS for existence,
    # so it is not emitted unless the caller asked for it by name.
    assert "networks" in estate.EXISTENCE_LICENSING
    assert tree.snapshot.networks is None
    assert tree.ledger.scope_of("networks") is provenance.UNCAPTURED


def test_include_refuses_a_category_outside_existence_licensing():
    with pytest.raises(ValueError, match="DEFAULT_EMIT"):
        estate.CaptureOptions(include=("firewall_rules",))
    with pytest.raises(ValueError, match="not one of"):
        estate.CaptureOptions(include=("permissions",))


def test_emit_refuses_a_category_terraform_may_not_speak_for():
    with pytest.raises(ValueError, match="resource_types"):
        estate.CaptureOptions(emit=("resource_types",))


# -- THE HEADLINE PIN, direction one: equality ---------------------------------


def test_the_tree_reproduces_the_estate_fixtures_records(tree, fixture_estate):
    for category in RECORD_PINS:
        produced = getattr(tree.snapshot, category)
        stored = getattr(fixture_estate, category)
        assert produced is not None, f"{category} was not emitted at all"
        shared = sorted(set(produced) & set(stored))
        assert shared, (
            f"{category}: the capture and the estate fixture share NO key, so "
            f"the equality assertion below would be vacuously true - that is "
            f"the key-form regression drift:key-mismatch exists to catch")
        for key in shared:
            assert produced[key] == stored[key], f"{category}: {key}"


# -- THE HEADLINE PIN, direction two: both directions --------------------------


def test_every_key_the_tree_produces_is_stored_or_listed_as_extra(
        everything, fixture_estate):
    produced = _produced(everything)
    for category, keys in sorted(produced.items()):
        stored = getattr(fixture_estate, category) or ()
        listed = DELIBERATELY_EXTRA.get(category, {})
        unaccounted = sorted(set(keys) - set(stored) - set(listed))
        assert not unaccounted, (
            f"{category}: the tree produces {unaccounted}, which the estate "
            f"fixture does not store and DELIBERATELY_EXTRA does not explain. "
            f"The two describe ONE estate: either the fixture is missing a row "
            f"or the key form regressed")


def test_every_estate_key_in_an_emitted_category_is_produced_or_listed(
        tree, fixture_estate):
    produced = _produced(tree)
    for category in tree.snapshot.captured_categories():
        stored = getattr(fixture_estate, category) or ()
        listed = DELIBERATELY_ABSENT.get(category, {})
        unaccounted = sorted(set(stored) - produced.get(category, set())
                             - set(listed))
        assert not unaccounted, (
            f"{category}: the estate fixture stores {unaccounted}, which the "
            f"tree does not produce and DELIBERATELY_ABSENT does not explain")


def test_every_listed_exception_is_still_a_real_one(everything, fixture_estate):
    """A stale allowance is worse than none: it silently excuses a key that has
    since started (or stopped) being produced."""
    produced = _produced(everything)
    for category, entries in DELIBERATELY_EXTRA.items():
        for key, reason in entries.items():
            assert reason.strip(), f"{category}/{key} is listed with no reason"
            assert key in produced.get(category, set()), (
                f"{category}/{key} is listed as deliberately extra but the tree "
                f"no longer produces it")
            assert key not in (getattr(fixture_estate, category) or ()), (
                f"{category}/{key} is listed as deliberately extra but the "
                f"estate fixture now stores it")
    for category, entries in DELIBERATELY_ABSENT.items():
        for key, reason in entries.items():
            assert reason.strip(), f"{category}/{key} is listed with no reason"
            assert key in (getattr(fixture_estate, category) or ()), (
                f"{category}/{key} is listed as deliberately absent but the "
                f"estate fixture no longer stores it")
            assert key not in produced.get(category, set()), (
                f"{category}/{key} is listed as deliberately absent but the "
                f"tree now produces it")


# -- terraform is never complete ----------------------------------------------


def test_no_scope_anywhere_in_a_terraform_capture_is_complete(tree, everything):
    for capture in (tree, everything):
        for category, scope in capture.ledger.categories.items():
            assert scope.scope != "complete", category
            assert not scope.existence_licensed, category
        for source_id, record in capture.ledger.sources.items():
            assert record.scope != "complete", source_id


def test_an_emitted_category_refuses_to_license_an_absence(tree):
    for category in estate.DEFAULT_EMIT:
        reason = provenance.require_complete(tree.ledger, category)
        assert reason is not None, category
        assert "absence" in reason


# -- drop-unresolved -----------------------------------------------------------


def test_a_record_with_a_nested_marker_is_dropped_whole_and_counted(tree):
    holed = "projects/acme-prod/global/firewalls/mixed-granularity"
    (row,) = [d for d in tree.dropped if d.key == holed]

    assert row.category == "firewall_rules"
    assert row.reason == "interpolation"
    assert row.path == "source_ranges"
    # NOT a shrunken version of it: the record carried literal priority and
    # direction beside the unresolvable source_ranges, and emitting it with the
    # ranges elided would read as MATCHES-NOTHING to every packet consumer.
    assert holed not in tree.snapshot.firewall_rules
    assert not [key for key in tree.snapshot.firewall_rules
                if key.endswith("/mixed-granularity")]


def test_a_dropped_record_costs_its_category_the_licence(tmp_path):
    _write(tmp_path, "one_hole.tf", ONE_HOLE_TF)

    capture = estate.capture(tmp_path, options=_options())

    assert sorted(capture.snapshot.firewall_rules) == [
        "projects/acme-prod/global/firewalls/solid"]
    assert [(d.key, d.reason) for d in capture.dropped] == [
        ("projects/acme-prod/global/firewalls/holed", "interpolation")]
    scope = capture.ledger.scope_of("firewall_rules")
    assert scope.dropped == 1 and scope.reasons == ("interpolation",)
    reason = provenance.require_complete(capture.ledger, "firewall_rules")
    assert "dropped 1 record(s) (interpolation)" in reason
    assert "known holes" in reason


def test_drop_unresolved_reads_the_key_as_well_as_the_record():
    """A flat vocabulary's name IS its content, so an unresolved key is the
    only way one can fail."""
    marker = facts.Unresolved("interpolation", "values.name")
    kept, dropped = estate.drop_unresolved([
        merge.Resolution("network_tags", marker, None,
                         provenance.FactOrigin(source_id="s")),
        merge.Resolution("network_tags", "web", None,
                         provenance.FactOrigin(source_id="s")),
    ])

    assert [r.key for r in kept] == ["web"]
    assert (dropped[0].path, dropped[0].reason) == ("<key>", "interpolation")
    assert "detail" not in dropped[0].key, "a marker renders through its own repr"


# -- never emit an empty category ---------------------------------------------


def test_an_emitted_category_with_no_survivor_is_omitted_not_emptied(tree):
    capture = estate.capture(TF_DIR, options=_options(include=("networks",)))

    assert "networks" not in capture.snapshot.to_dict()
    assert capture.snapshot.networks is None
    scope = capture.ledger.scope_of("networks")
    assert scope.scope == "uncaptured" and scope.keys == 0
    assert estate.EMPTY_CATEGORY_NOTE in scope.note
    # A lookup against it answers UNKNOWN, and UNKNOWN refuses truthiness, so
    # "no terraform-managed networks" cannot be read as "no networks".
    assert capture.snapshot.network_exists(
        "projects/acme-prod/global/networks/vpc-main") is UNKNOWN
    with pytest.raises(TypeError):
        bool(capture.snapshot.network_exists(
            "projects/acme-prod/global/networks/vpc-main"))


# -- the strict construction path ---------------------------------------------


def test_a_malformed_org_policy_key_raises_at_capture_time():
    bad = facts.Fact(
        category="org_policies",
        key="projects/acme-prod|constraints/compute.disableSerialPortAccess",
        record={"node": "projects/somewhere-else",
                "constraint": "constraints/compute.disableSerialPortAccess",
                "rules": []},
        source="tfstate", origin="s1", address="google_org_policy_policy.bad")
    result = merge.resolve([bad], sources=[
        SourceRecord("s1", "tfstate", scope="partial", captured_at=PINNED)])

    with pytest.raises(ValueError) as caught:
        estate.build(result, options=estate.CaptureOptions(captured_at=PINNED),
                     sources=[SourceRecord("s1", "tfstate", scope="partial")])

    message = str(caught.value)
    assert "org_policies" in message
    assert "projects/acme-prod|constraints/compute.disableSerialPortAccess" in message
    assert "projects/somewhere-else" in message


# -- the redaction boundary ----------------------------------------------------


def test_the_boundary_converts_every_redacted_object_to_its_wire_string():
    secret = redact.Redacted.of("FIXTURE-SECRET-DO-NOT-LEAK", "bindings[0].note")
    fact = facts.Fact(
        category="iam_bindings",
        key="//cloudresourcemanager.googleapis.com/projects/acme-prod",
        record={"bindings": [{"role": "roles/viewer",
                              "members": ["user:alice@acme.example"],
                              "note": secret}]},
        source="tfstate", origin="s1", address="google_project_iam_binding.x")
    result = merge.resolve([fact], sources=[
        SourceRecord("s1", "tfstate", scope="partial", captured_at=PINNED)])

    capture = estate.build(result, options=estate.CaptureOptions(captured_at=PINNED),
                           sources=[SourceRecord("s1", "tfstate", scope="partial")])

    stored = capture.snapshot.iam_bindings[
        "//cloudresourcemanager.googleapis.com/projects/acme-prod"]
    assert stored["bindings"][0]["note"] == secret.wire()
    assert redact.is_wire(stored["bindings"][0]["note"])
    # The snapshot must be json.dumps-able, which a frozen dataclass is not...
    assert "FIXTURE-SECRET-DO-NOT-LEAK" not in json.dumps(capture.snapshot.to_dict())
    # ...and a check reading it still abstains, because the wire spelling is
    # the same fact on the other side of the boundary.
    assert redact.has_redacted(capture.snapshot.iam_bindings) is True


# -- THE SECRETS PIN -----------------------------------------------------------


@pytest.mark.parametrize("sentinel", ("FIXTURE-SECRET-DO-NOT-LEAK",
                                      "FIXTURE-SECRET-BY-NAME"))
def test_no_written_byte_carries_a_planted_secret(tmp_path, sentinel):
    assert sentinel in STATE_PATH.read_text(encoding="utf-8"), (
        "the input must actually carry the sentinel, or a redactor that does "
        "nothing passes this by accident")

    capture = estate.capture(TF_DIR, options=_options(captured_at=PINNED))
    snapshot_path, ledger_path = estate.write_capture(
        capture, tmp_path / "terraform-snapshot.json")

    for written in (snapshot_path, ledger_path):
        assert sentinel.encode() not in Path(written).read_bytes(), written
    assert sentinel not in provenance.summarize(capture.ledger)
    assert not [note for note in capture.notes if sentinel in note]


# -- captured_at ---------------------------------------------------------------


def test_captured_at_is_the_oldest_artifact_mtime(tmp_path):
    older = _write(tmp_path, "older.tf", PLAIN_TF)
    newer = _write(tmp_path, "newer.tf", PLAIN_TF.replace("plain", "newer"))
    os.utime(older, (1_700_000_000, 1_700_000_000))
    os.utime(newer, (1_800_000_000, 1_800_000_000))

    capture = estate.capture(tmp_path, options=_options())

    expected = datetime.fromtimestamp(1_700_000_000, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    assert capture.snapshot.captured_at == expected, (
        "worst-case freshness is the only honest default when several "
        "artifacts of different ages are combined")
    # every per-artifact mtime, listed separately
    assert sorted(a.mtime for a in capture.ledger.artifacts) == [
        1_700_000_000.0, 1_800_000_000.0]
    assert sorted(os.path.basename(a.path) for a in capture.ledger.artifacts) == [
        "newer.tf", "older.tf"]
    # and the caveat, in plain words, on every source the fallback stamped
    assert capture.ledger.sources
    for record in capture.ledger.sources.values():
        assert estate.MTIME_CAVEAT in record.note
    assert "FILE MODIFICATION TIME" in estate.MTIME_CAVEAT


def test_the_mtime_stamp_agrees_with_the_readers():
    # One rendering of one instant. A capture whose snapshot stamp and whose
    # source records disagreed by a format would be undiffable across runs.
    for mtime in (0.0, 1_700_000_000.0, 1_785_829_454.98):
        assert estate._mtime_stamp(mtime) == tfstate_reader.mtime_utc(mtime)


def test_an_explicit_captured_at_replaces_the_mtime_and_drops_the_caveat():
    capture = estate.capture(TF_DIR, options=_options(captured_at=PINNED))

    assert capture.snapshot.captured_at == PINNED
    for record in capture.ledger.sources.values():
        assert estate.MTIME_CAVEAT not in record.note, (
            "the caveat would be false once the caller stamped the capture")


def test_a_capture_with_no_artifact_and_no_override_refuses(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    with pytest.raises(ValueError, match="defensible captured_at"):
        estate.capture(empty, options=_options())


# -- a reader that fails does not shrink the capture ---------------------------


def test_a_reader_that_raises_becomes_a_note_and_the_rest_still_captures(
        monkeypatch):
    def boom(path, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(tfstate_reader, "read_state", boom)
    capture = estate.capture(TF_DIR, options=_options(captured_at=PINNED))

    assert estate.READER_FAILED.format(
        path=str(STATE_PATH), kind="tfstate",
        error="RuntimeError: boom") in capture.notes
    # the plan and the configuration still capture: one lost artifact costs one
    # artifact's coverage, never the run.
    assert capture.snapshot.firewall_rules
    assert capture.snapshot.org_policies
    assert str(STATE_PATH) not in capture.ledger.sources
    assert str(STATE_PATH) not in [a.path for a in capture.ledger.artifacts]


# -- write_capture -------------------------------------------------------------


def _capture_into(directory):
    capture = estate.capture(TF_DIR, options=_options(captured_at=PINNED))
    return estate.write_capture(capture, Path(directory) / "terraform-snapshot.json")


def test_write_capture_writes_exactly_two_files(tmp_path):
    out = tmp_path / "out"
    out.mkdir()

    snapshot_path, ledger_path = _capture_into(out)

    assert sorted(p.name for p in out.iterdir()) == [
        "terraform-snapshot.json", "terraform-snapshot.origins.json"]
    assert ledger_path == provenance.origins_path(snapshot_path)
    # both are readable back through their own loaders
    assert GcpSnapshot.load(snapshot_path).captured_at == PINNED
    assert provenance.SourceLedger.load(ledger_path).schema == provenance.SCHEMA


def test_two_runs_over_unchanged_inputs_are_byte_identical(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()

    left = _capture_into(first)
    right = _capture_into(second)

    for one, other in zip(left, right):
        assert Path(one).read_bytes() == Path(other).read_bytes(), one
    # the sidecar is multi-line and newline-terminated, because the workflow it
    # serves is committing an estate and reviewing drift BY DIFF
    text = Path(left[1]).read_text(encoding="utf-8")
    assert text.endswith("\n") and text.count("\n") > 1


def test_an_empty_capture_still_writes_a_ledger(tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    out = tmp_path / "out"
    out.mkdir()

    capture = estate.capture(empty, options=_options(captured_at=PINNED))
    snapshot_path, ledger_path = estate.write_capture(
        capture, out / "terraform-snapshot.json")

    assert capture.snapshot.captured_categories() == ()
    assert sorted(p.name for p in out.iterdir()) == [
        "terraform-snapshot.json", "terraform-snapshot.origins.json"]
    ledger = provenance.SourceLedger.load(ledger_path)
    assert sorted(ledger.categories) == sorted(estate.DEFAULT_EMIT)
    for category in estate.DEFAULT_EMIT:
        scope = ledger.scope_of(category)
        assert scope.scope == "uncaptured" and scope.keys == 0
        assert provenance.require_complete(ledger, category) is not None
    assert json.loads(Path(snapshot_path).read_text(encoding="utf-8")) == {
        "captured_at": PINNED}


# -- existence licensing -------------------------------------------------------


def _api_result():
    """A DECLARED-complete, non-terraform fact set. ``estate.build`` is
    source-agnostic, and the licence is only ever visible where a caller
    declared a source complete - a terraform kind is capped at ``partial``."""
    rows = [
        facts.Fact(category="access_levels",
                   key="accessPolicies/987/accessLevels/trusted_corp",
                   source="api", origin="api-1", address="accessLevels.list"),
        facts.Fact(category="network_tags", key="web", source="api",
                   origin="api-1", address="firewalls.list"),
    ]
    record = SourceRecord("api-1", "api", scope="complete", captured_at=PINNED)
    return merge.resolve(rows, sources=[record]), [record]


def test_opting_in_sets_the_existence_licence_and_declining_withholds_it():
    result, sources = _api_result()

    opted = estate.build(result, sources=sources, options=estate.CaptureOptions(
        captured_at=PINNED, include=("access_levels",)))
    declined = estate.build(result, sources=sources, options=estate.CaptureOptions(
        captured_at=PINNED))

    licensed = opted.ledger.scope_of("access_levels")
    assert licensed.existence_licensed is True
    assert estate.LICENSING_WARNING in licensed.note
    assert provenance.require_complete(opted.ledger, "access_levels") is None
    # declining is not "emit it unlicensed": the category is not emitted at all
    assert declined.snapshot.access_levels is None
    assert declined.ledger.scope_of("access_levels").scope == "uncaptured"
    # and a DEFAULT_EMIT category never licenses an absence, complete or not
    assert opted.ledger.scope_of("network_tags").existence_licensed is False
    assert "existence licence" in provenance.require_complete(
        opted.ledger, "network_tags")


def test_opting_in_over_a_terraform_capture_still_licenses_nothing():
    """THE POINT of the opt-in warning. The flag is asked for, the scope is
    partial, and CategoryScope narrows the licence away - a terraform-only view
    answering False for a name it never enumerated is a manufactured false
    positive, not a finding."""
    capture = estate.capture(TF_DIR, options=_options(
        include=("cloud_armor_policies",), captured_at=PINNED))

    scope = capture.ledger.scope_of("cloud_armor_policies")
    assert capture.snapshot.cloud_armor_policies is not None
    assert scope.scope == "partial"
    assert scope.existence_licensed is False
    assert estate.LICENSING_WARNING in scope.note
    assert any(estate.LICENSING_WARNING in note for note in capture.notes)


# -- the ledger travels with everything it explains ----------------------------


def test_every_emitted_key_has_an_origin_and_every_origin_names_a_source(tree):
    for category in tree.snapshot.captured_categories():
        for key in getattr(tree.snapshot, category):
            origin = tree.ledger.origin_of(category, key)
            assert origin is not None, f"{category}/{key} has no origin"
            assert origin.source_id in tree.ledger.sources
            assert tree.ledger.by_locator(origin.locator, category=category), (
                f"{category}/{key} names locator {origin.locator!r}, which "
                f"indexes nothing")


def test_completeness_is_never_inferred_from_content(tmp_path):
    """A source that contributed facts but was never declared is COVERED and
    unlicensed - never complete, however much content it produced."""
    rows = [facts.Fact(category="network_tags", key=name, source="tfstate",
                       origin="undeclared-source", address=f"fw.{name}")
            for name in ("web", "db", "bastion")]
    result = merge.resolve(rows)

    capture = estate.build(result, options=estate.CaptureOptions(captured_at=PINNED))

    assert sorted(capture.snapshot.network_tags) == ["bastion", "db", "web"]
    scope = capture.ledger.scope_of("network_tags")
    assert scope.scope == "undeclared"
    assert provenance.require_complete(capture.ledger, "network_tags") is not None
    record = capture.ledger.sources["undeclared-source"]
    assert record.scope == "undeclared"
    # the fidelity SPELLING is known even when the coverage is not, so it is
    # carried rather than flattened to 'unattributed'
    assert record.kind == "tfstate"
