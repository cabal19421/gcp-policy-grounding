"""THE BEHAVIOURAL CONTRACT of the reconciliation spine, as one table.

Nine cases over two overlapping views of one estate: agree, benign, dangerous,
stale, partial, unmergeable, superseded, boundary-demoted and key-mismatched.
Every one asserts the EXACT status, the EXACT kind and a named substring of the
message — never merely that something was reported.

THE API SIDE IS NOT A NEW FIXTURE. It is ``tests/fixtures/gcp/estate_snapshot
.json``, stamped at test time through :class:`provenance.LedgerBuilder` as an
``api`` capture complete in every category it holds, so a record-schema change
there surfaces here instead of rotting in a stale duplicate. The terraform side
is the five committed snapshot/sidecar pairs in ``fixtures/gcp/drift/``, each
carrying only the fields its case asserts on.

TWO PROPERTIES OF THE SPINE THIS MODULE LEANS ON, both verified rather than
assumed, and both the reason some assertions sit one layer below the CLI:

- MERGE STEP 7 REPORTS A DIFFERING VALUE AND LEAVES ABSENCE TO STEP 8. A field
  one view carries and the other does not is not a dispute, whatever its
  severity, so a benign or unmergeable difference reaches ``drift`` only as a
  value-versus-value pair (or, for an unmergeable, as a shape ``compare``
  refuses to normalise at all). The frozen estate record carries no
  ``description``, which is why the benign arm is driven through a merge of two
  terraform views of the SAME committed record.
- ``sources.LoadedSource.record()`` declares every loaded source ``undeclared``
  at the SOURCE level and carries the real coverage per category, so the two
  rules that read a SOURCE record — ``drift``'s phantom carve-out and
  ``compose_scope``'s boundary — are exercised over an explicitly declared
  ``merge.resolve`` of the same two fixtures.

Environment-honest: an autouse fixture scrubs every ``GCP_GROUNDING_*``
variable, and the clock is pinned on every run, so no assertion here can drift
with the wall clock or with a developer's exported snapshot. There is no
``HAVE_Z3`` branch because nothing here needs one: every assertion is over the
current-state verdict families, which the solver backend does not touch, and
:func:`test_the_matrix_through_the_cli` pins that independence rather than
assuming it. In-process throughout: NO subprocess is spawned, so the whole
matrix stays off the suite-wide spawn budget.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

import pytest

from gcp_grounding import (compare, drift, estate, facts, freshness, merge,
                           provenance, sources)
from gcp_grounding.cli import EXIT_FAILED, EXIT_OK, main
from gcp_grounding.core.report import Verdict
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.provenance import SourceLedger, SourceRecord
from gcp_grounding.reconciled import ReconciledSnapshot, reads

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
DRIFT_DIR = FIXTURES / "drift"
ESTATE = FIXTURES / "estate_snapshot.json"
POLICY = FIXTURES / "policies" / "iam_policy_good.json"

#: The API side's stamp, its origin and its scope — the three things
#: ``LedgerBuilder`` needs to make the estate fixture a declared API capture.
API_ID = "api-capture"
API_ORIGIN = "compute.firewalls.list"
API_CAPTURED_AT = "2026-07-18T09:30:00Z"

#: Both pinned clocks. Every fixture is dated 2026-07 (2026-05 for the stale
#: one), so a run without a pinned clock would go stale with the wall clock.
NOW = "2026-07-19T00:00:00Z"
STALE_NOW = "2026-08-01T00:00:00Z"

LINEAGE = "8b1a0000-0000-4000-8000-000000000001"
INTERNAL = "projects/acme-prod/global/firewalls/allow-internal"
DENY = "projects/acme-prod/global/firewalls/deny-ssh-external"
WORLD = "projects/acme-prod/global/firewalls/allow-ssh-world"

#: The verdict kinds this matrix is about: the whole current-state family. The
#: policy's OWN verdicts are deliberately excluded — they depend on the solver
#: backend, and nothing here does.
STATE_KINDS = frozenset(drift.DRIFT_KINDS + sources.PROVENANCE_KINDS
                        + freshness.STALENESS_KINDS)


@pytest.fixture(autouse=True)
def _state_env_off(monkeypatch):
    """No case here inherits a developer's exported state configuration."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)


# -- the two sides ------------------------------------------------------------


def estate_record(key: str) -> dict:
    return json.loads(ESTATE.read_text(encoding="utf-8"))["firewall_rules"][key]


def tf_record(name: str, key: str) -> dict:
    document = json.loads((DRIFT_DIR / f"{name}.json").read_text(encoding="utf-8"))
    return document["firewall_rules"][key]


def api_ledger() -> SourceLedger:
    """The frozen estate fixture as a DECLARED api capture: one source, every
    captured category at scope ``complete``."""
    snapshot = GcpSnapshot.load(ESTATE)
    builder = provenance.LedgerBuilder()
    builder.source(API_ID, "api", origin=API_ORIGIN, captured_at=API_CAPTURED_AT,
                   scope="complete")
    for category in snapshot.captured_categories():
        builder.declare(category, scope="complete", source_kinds=("api",))
    return builder.build()


@pytest.fixture
def api_origins(tmp_path) -> str:
    path = tmp_path / "api.origins.json"
    api_ledger().write(path)
    return str(path)


def write_source(tmp_path, name: str, document: dict, rows: dict, *,
                 captured_at=NOW, serial: int = 7, origin: str = "state.tfstate"
                 ) -> str:
    """One uncommitted terraform-side source: a snapshot plus its sidecar."""
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    builder = provenance.LedgerBuilder()
    builder.source("tf-state", "tfstate", origin=origin, captured_at=captured_at,
                   scope="partial", serial=serial, lineage=LINEAGE)
    for category, keys in rows.items():
        builder.declare(category, scope="partial", source_kinds=("tfstate",))
        for key, locator in keys.items():
            builder.fact(category, key, source_id="tf-state", locator=locator)
    builder.build().write(provenance.origins_path(path))
    return str(path)


def current(primary, *, extra=(), origins=None, now=NOW, **kwargs):
    """``sources.load_current`` over an explicit source set."""
    state = sources.load_current(sources.SourceOptions(
        primary=str(primary), origins=origins,
        extra=tuple(str(path) for path in extra), now=now, **kwargs))
    assert state.ok, state.problem
    return state


def two_source(name, **kwargs):
    """The estate fixture (declared complete) plus one committed terraform
    fixture — the matrix's standard pair."""
    return current(ESTATE, extra=(DRIFT_DIR / f"{name}.json",), **kwargs)


def notes_of(state, *kinds) -> list[Verdict]:
    """The current-state notes of EXACTLY these kinds — never a prefix match,
    which would fold ``drift:unmanaged`` into ``drift``."""
    wanted = frozenset(kinds)
    return [note for note in state.notes if note.kind in wanted]


# -- the explicitly declared merge --------------------------------------------


def declared_merge(name: str, *, api_boundary: str = "", tf_boundary: str = ""):
    """The SAME two fixtures, merged with each side's coverage declared on its
    own :class:`SourceRecord` — which is what ``drift``'s phantom carve-out and
    ``compose_scope``'s boundary read.

    ``sources.LoadedSource.record()`` deliberately flattens every loaded source
    to ``undeclared`` and carries the real coverage per category, so those two
    rules are unreachable from ``load_current``; everything else in this module
    goes through the loader.
    """
    api = SourceRecord(source_id=API_ID, kind="api", origin=API_ORIGIN,
                       captured_at=API_CAPTURED_AT, scope="complete",
                       boundary=api_boundary)
    tfs = SourceRecord(source_id="tf-state", kind="tfstate",
                       origin="envs/prod/terraform.tfstate",
                       captured_at="2026-07-17T12:00:00Z", scope="partial",
                       boundary=tf_boundary, serial=7, lineage=LINEAGE)
    collected = list(sources.snapshot_facts(
        GcpSnapshot.load(ESTATE), source="api", origin=API_ID))
    collected += list(sources.snapshot_facts(
        GcpSnapshot.load(DRIFT_DIR / f"{name}.json"), source="tfstate",
        origin="tf-state"))
    result = merge.resolve(collected, sources=[api, tfs])
    emitted = {resolution.category for resolution in result.resolutions}
    capture = estate.build(result, options=estate.CaptureOptions(
        emit=tuple(c for c in facts.TF_CATEGORIES if c in emitted),
        captured_at="2026-07-17T12:00:00Z"), sources=[api, tfs])
    snapshot = ReconciledSnapshot.from_snapshot(
        capture.snapshot, ledger=capture.ledger, disputes=result.disputes,
        policy_name=merge.DEFAULT_PRECEDENCE)
    return result, snapshot


def graded(snapshot, status: str, read_set, *, target=INTERNAL) -> Verdict:
    """One verdict of *status* re-graded against *read_set*."""
    return drift.adjudicate([Verdict(status, "firewall", target, 0, "a finding")],
                            read_set, snapshot)[0]


def sweep(snapshot, status: str) -> Verdict:
    """AN ESTATE CHECK THAT ITERATES THE FIREWALL TABLE, simulated.

    Simulated rather than borrowed: no check in this tree sweeps the firewall
    table — nothing outside ``knowledge`` and ``reconciled`` so much as calls
    ``firewall_rules_for_network`` — so the alternative to a local function is
    asserting nothing. It reads the whole category AND every row, which is what
    "iterates the table" means and what makes the read set something the taint
    rules can grade.
    """
    with reads("firewall-sweep") as read_set:
        for key in snapshot.firewall_rules or {}:
            snapshot.firewall_rule(key)
    return graded(snapshot, status, read_set.reads, target="firewall-sweep")


# -- 1: agree ------------------------------------------------------------------


def test_an_agreeing_terraform_view_reports_only_coverage(api_origins):
    """Byte-equivalent records disagree about nothing, so what is left is
    exactly the two things a second source always costs: the multi-source
    provenance note, and one aggregate per category the complete API
    enumeration holds facts terraform does not manage."""
    state = two_source("tf_agree", origins=api_origins)
    assert notes_of(state, drift.DRIFT_MATERIAL, drift.DRIFT_UNMERGEABLE,
                    drift.DRIFT) == []

    unmanaged = notes_of(state, drift.DRIFT_UNMANAGED)
    assert [(v.status, v.kind, v.target) for v in unmanaged] == [
        ("unverified", drift.DRIFT_UNMANAGED, "firewall_rules"),
        ("unverified", drift.DRIFT_UNMANAGED, "network_tags")]
    assert "3 resource(s) exist in the estate" in unmanaged[0].message
    assert "UNMANAGED RESOURCES ARE EXPECTED" in unmanaged[0].message
    assert "1 resource(s) exist in the estate" in unmanaged[1].message

    provenance_notes = notes_of(state, "provenance")
    assert len(provenance_notes) == 1
    assert provenance_notes[0].status == "unverified"
    assert "merged from 2 sources" in provenance_notes[0].message


# -- 2: benign -----------------------------------------------------------------


def test_a_benign_difference_is_reported_once_and_taints_nothing(api_origins):
    """THE REPORTED-VERSUS-IGNORED SPLIT, in the one place both kinds are
    present together, and the promise that being reported costs nothing.

    The fixture carries a ``description`` the estate record does not have plus
    an ``etag`` and a ``fingerprint``: ``compare`` yields ONE diff and it is the
    description — the two volatile fields yield no ``FieldDiff`` at all, which
    is why two views of one unchanged rule do not emit a wall of etag drift.

    The benign ``drift`` VERDICT is driven through a merge of two terraform
    views of that same committed record, because a field present on one side
    only is an ABSENCE and merge step 7 leaves absence to step 8 — the frozen
    estate record carries no description of its own, so the value-versus-value
    pair is the only shape that reaches drift's benign arm at all.
    """
    record = tf_record("tf_benign", INTERNAL)
    diffs = compare.compare("firewall_rules", estate_record(INTERNAL), record)
    assert [(d.field, d.severity) for d in diffs] == [("description", compare.BENIGN)]
    assert {"etag", "fingerprint"} <= compare.VOLATILE_IGNORED

    twin = dict(record, description="internal traffic", etag="b3RoZXI=",
                fingerprint="Zm9vYmFy")
    result = merge.resolve(
        [facts.Fact(category="firewall_rules", key=INTERNAL, record=side,
                    source="tfstate", origin=workspace,
                    address="google_compute_firewall.allow_internal")
         for side, workspace in ((record, "workspace-a"), (twin, "workspace-b"))],
        sources=[SourceRecord(source_id=w, kind="tfstate", scope="partial")
                 for w in ("workspace-a", "workspace-b")])
    assert [(d.severity, d.field) for d in result.disputes] == [("benign", "description")]

    verdicts = drift.drift_verdicts(SourceLedger(disputes=result.disputes))
    assert len(verdicts) == 1
    assert (verdicts[0].status, verdicts[0].kind) == ("unverified", drift.DRIFT)
    assert "'description'" in verdicts[0].message
    assert "NO CHECK WAS AFFECTED" in verdicts[0].message

    # BENIGN DRIFT DOES NOT TAINT: the fact stays clean end to end, and a check
    # reading the rule keeps the answer it computed.
    state = two_source("tf_benign", origins=api_origins)
    assert state.ledger.taint_of("firewall_rules", INTERNAL) == ""
    with reads("firewall") as read_set:
        state.snapshot.firewall_rule(INTERNAL)
    assert graded(state.snapshot, "grounded", read_set.reads).status == "grounded"


# -- 3: dangerous --------------------------------------------------------------


def test_a_material_field_conflict_names_the_field_and_stops_a_pass(api_origins):
    """``disabled`` true against the API's false: one ``drift:material`` naming
    the field, and a ``grounded`` that read the rule downgraded to
    ``unverified`` with the not-decided clause."""
    state = two_source("tf_dangerous", origins=api_origins)
    material = [v for v in notes_of(state, drift.DRIFT_MATERIAL)
                if v.target.endswith(DENY)]
    assert len(material) == 1
    assert (material[0].status, material[0].kind) == ("unverified", drift.DRIFT_MATERIAL)
    assert "the security field 'disabled'" in material[0].message
    assert "'False' against 'True'" in material[0].message
    assert state.ledger.taint_of("firewall_rules", DENY) == "disputed"

    with reads("firewall") as read_set:
        state.snapshot.firewall_rule(DENY)
    downgraded = graded(state.snapshot, "grounded", read_set.reads, target=DENY)
    assert downgraded.status == "unverified"
    assert "[not decided:" in downgraded.message
    assert f"firewall_rules/{DENY} is tainted 'disputed'" in downgraded.message


def test_a_terraform_only_rule_is_kept_disputed_and_blocks_nothing(api_origins):
    """A rule the COMPLETE API enumeration does not contain: one
    ``drift:material`` saying it may be gone, the fact PRESENT in the merged
    snapshot and tainted, and — the marquee — a check that iterates the
    firewall table still emits its ``contradicted``."""
    state = two_source("tf_dangerous", origins=api_origins)
    material = [v for v in notes_of(state, drift.DRIFT_MATERIAL)
                if v.target.endswith(WORLD)]
    assert len(material) == 1
    assert (material[0].status, material[0].kind) == ("unverified", drift.DRIFT_MATERIAL)
    assert "MAY HAVE BEEN DESTROYED OR MOVED OUT OF BAND" in material[0].message
    assert "enumerated 'firewall_rules' completely" in material[0].message

    # KEPT, never dropped: dropping it would let the merged view prove an
    # absence that is not proven.
    assert WORLD in (state.snapshot.firewall_rules or {})
    assert state.ledger.taint_of("firewall_rules", WORLD) == "disputed"

    _result, declared = declared_merge("tf_dangerous")
    assert sweep(declared, "contradicted").status == "contradicted"
    downgraded = sweep(declared, "grounded")
    assert downgraded.status == "unverified"
    assert "[not decided:" in downgraded.message


def test_a_phantom_only_finding_is_downgraded_and_one_more_fact_keeps_it():
    """THE ONE PLACE the anti-suppressor rule and the anti-false-block rule pull
    in opposite directions, and the two arms only make sense side by side.

    A finding whose ENTIRE read set is the terraform-only rule rests on an
    existence the complete API enumeration refutes, so it is DOWNGRADED naming
    the phantom fact and both sources — in hook mode the alternative is exit 2
    against a legitimate change on the strength of a resource the authoritative
    source says is gone. The same finding with ONE more undisputed rule in its
    read set KEEPS its ``contradicted``: the anti-suppressor argument does hold
    for a finding with evidence beyond the phantom.
    """
    _result, snapshot = declared_merge("tf_dangerous")
    alone = graded(snapshot, "contradicted", [("firewall_rules", WORLD)],
                   target=WORLD)
    assert alone.status == "unverified"
    assert "PHANTOM" in alone.message
    assert f"'firewall_rules/{WORLD}' is present only in 'tf-state'" in alone.message
    assert f"ABSENT from '{API_ID}'" in alone.message

    with_evidence = graded(snapshot, "contradicted",
                           [("firewall_rules", WORLD), ("firewall_rules", DENY)],
                           target=WORLD)
    assert with_evidence.status == "contradicted"
    assert "[not decided:" not in with_evidence.message


# -- 4: stale ------------------------------------------------------------------


def test_a_stale_source_abstains_and_can_ground_nothing(monkeypatch):
    """Ninety-two days old under the DEFAULT seven-day ceiling and no
    ``--max-age``: one ``staleness`` verdict per SOURCE naming the day count and
    the limit, every category it supplies refusing to license an absence, and a
    name only it carries answering ``unverified`` rather than ``grounded``."""
    monkeypatch.setenv(freshness.NOW_ENV, STALE_NOW)
    state = current(DRIFT_DIR / "tf_stale.json", now=None)

    stale = notes_of(state, *freshness.STALENESS_KINDS)
    assert len(stale) == 1
    assert (stale[0].status, stale[0].kind, stale[0].target) == (
        "unverified", "staleness", "tf-state")
    assert "92 days before now" in stale[0].message
    assert f"past the {freshness.MAX_AGE_DEFAULT.days} days freshness limit" \
        in stale[0].message

    # The DEMOTION sets the scope AND the taint, and require_complete answers
    # with the more specific uncaptured arm — a demoted category is not merely
    # doubtful, it no longer counts as captured at all.
    for category in ("firewall_rules", "network_tags"):
        scope = state.ledger.scope_of(category)
        assert (scope.scope, scope.taint) == ("uncaptured", "stale")
        assert provenance.require_complete(state.ledger, category) == (
            f"this check reasons from absence, but category '{category}' was not "
            f"captured - an uncaptured category cannot be read as an empty one")

    with reads("tag") as read_set:
        assert state.snapshot.network_tag_exists("web") is True
    answer = graded(state.snapshot, "grounded", read_set.reads, target="web")
    assert answer.status == "unverified"
    assert "network_tags/web is tainted 'stale'" in answer.message


# -- 5: partial ----------------------------------------------------------------


def test_a_partial_terraform_source_licenses_no_absence():
    """With NO API source at all the whole current state is one ``partial``
    terraform capture, so absence in it is not absence — stated as the exact
    refusal naming the origin, and as an ``unverified`` verdict of kind
    ``scope``."""
    state = current(DRIFT_DIR / "tf_partial.json")
    assert provenance.require_complete(state.ledger, "firewall_rules") == (
        "this check reasons from absence, but category 'firewall_rules' has "
        "partial coverage from tfstate with no declared boundary - absence "
        "within a partial capture is not absence")
    verdict = provenance.scope_verdict(state.ledger, "firewall_rules")
    assert (verdict.status, verdict.kind, verdict.target) == (
        "unverified", "scope", "firewall_rules")


# -- 6: unmergeable ------------------------------------------------------------


def test_an_unrecognised_field_is_unmergeable_and_taints_the_fact(
        tmp_path, api_origins):
    """A firewall record carrying a field no list classifies. It sits INSIDE the
    ``layer4`` entry, which is the shape that reaches the unmergeable arm from
    ONE side: a top-level unknown key present only in terraform is an absence,
    and merge step 7 leaves absence to step 8, whereas a layer4 entry the
    canonical protocol/ports form cannot hold makes the two views incomparable
    outright."""
    document = {"captured_at": "2026-07-17T12:00:00Z", "firewall_rules": {
        INTERNAL: dict(estate_record(INTERNAL),
                       layer4=[{"protocol": "tcp", "ports": ["0-65535"],
                                "log_config": True}])}}
    path = write_source(tmp_path, "tf_unmergeable", document,
                        {"firewall_rules": {INTERNAL: "google_compute_firewall."
                                                      "allow_internal"}},
                        captured_at="2026-07-17T12:00:00Z")
    state = current(ESTATE, extra=(path,), origins=api_origins)

    unmergeable = notes_of(state, drift.DRIFT_UNMERGEABLE)
    assert len(unmergeable) == 1
    assert (unmergeable[0].status, unmergeable[0].kind) == (
        "unverified", drift.DRIFT_UNMERGEABLE)
    assert "'log_config'" in unmergeable[0].message
    assert "could not be merged" in unmergeable[0].message
    assert state.ledger.taint_of("firewall_rules", INTERNAL) == "unmergeable"

    with reads("firewall") as read_set:
        state.snapshot.firewall_rule(INTERNAL)
    downgraded = graded(state.snapshot, "grounded", read_set.reads)
    assert downgraded.status == "unverified"
    assert "is tainted 'unmergeable'" in downgraded.message


# -- 7: superseded -------------------------------------------------------------


def test_a_state_file_that_moved_on_is_one_serial_verdict_naming_both(tmp_path):
    """The tfstate on disk is at serial 8 on the lineage the sidecar recorded at
    serial 7, read through the DEFAULT ``freshness`` reader rather than an
    injected one — so the path, the size guard and the header projection are all
    the real ones."""
    live = tmp_path / "live.tfstate"
    live.write_text(json.dumps({"version": 4, "serial": 8, "lineage": LINEAGE,
                                "terraform_version": "1.9.5", "outputs": {},
                                "resources": []}), encoding="utf-8")
    document = {"captured_at": "2026-07-17T12:00:00Z",
                "firewall_rules": {INTERNAL: estate_record(INTERNAL)}}
    path = write_source(tmp_path, "tf_superseded", document,
                        {"firewall_rules": {INTERNAL: "google_compute_firewall."
                                                      "allow_internal"}},
                        captured_at="2026-07-17T12:00:00Z", serial=7,
                        origin=str(live))
    state = current(path)

    superseded = notes_of(state, *freshness.STALENESS_KINDS)
    assert len(superseded) == 1
    assert (superseded[0].status, superseded[0].kind) == (
        "unverified", "staleness:serial")
    assert "captured at tfstate serial 7" in superseded[0].message
    assert "the file on disk is at serial 8" in superseded[0].message


# -- 8: the boundary demotion --------------------------------------------------


@pytest.mark.parametrize("tf_boundary", ["projects/acme-prod", ""])
def test_two_boundaries_that_are_not_identical_demote_the_composed_scope(
        tf_boundary):
    """Complete-within-'organizations/1' and complete are different claims, and
    so are two different withins.

    THE EMPTY-VERSUS-NAMED ARM IS THE ONE A NAIVE IMPLEMENTATION GETS WRONG: a
    boundary-less terraform source composed with an API capture complete within
    one organization would otherwise yield ``complete`` with NO boundary at all,
    licensing an estate-wide negative over merged content that includes projects
    outside it. Both arms demote to ``partial`` with the empty boundary, and the
    control below shows the emptiness is the DEMOTION and not merely the
    terraform cap: a boundary both sides share survives composition.
    """
    assert provenance.compose_scope(
        ("complete", "organizations/1"), ("partial", tf_boundary)) == ("partial", "")
    assert provenance.compose_scope(
        ("complete", "organizations/1"), ("complete", "organizations/1")) == \
        ("complete", "organizations/1")

    result, snapshot = declared_merge("tf_agree", api_boundary="organizations/1",
                                      tf_boundary=tf_boundary)
    scope = result.scopes["firewall_rules"]
    assert (scope.scope, scope.boundary) == ("partial", "")
    assert snapshot.ledger.scope_of("firewall_rules").boundary == ""
    refusal = provenance.require_complete(snapshot.ledger, "firewall_rules")
    assert refusal is not None and "no declared boundary" in refusal

    shared = declared_merge("tf_agree", api_boundary="organizations/1",
                            tf_boundary="organizations/1")[0]
    assert shared.scopes["firewall_rules"].boundary == "organizations/1"


# -- 9: the systematic-miss diagnostic -----------------------------------------


def _keyed_source(tmp_path, name: str, project: str) -> str:
    prefix = f"projects/{project}/global/firewalls/"
    record = estate_record(INTERNAL)
    keys = {f"{prefix}alpha": "google_compute_firewall.alpha",
            f"{prefix}beta": "google_compute_firewall.beta"}
    return write_source(
        tmp_path, name,
        {"captured_at": "2026-07-17T12:00:00Z",
         "firewall_rules": {key: record for key in keys}},
        {"firewall_rules": keys}, captured_at="2026-07-17T12:00:00Z")


def test_a_key_form_mismatch_is_one_diagnostic_and_matching_forms_none(tmp_path):
    """THE FAILURE BEING CAUGHT IS SILENCE. Two terraform sources keyed by
    project NUMBER and project ID, NEITHER complete: without this diagnostic the
    run yields two rows for one resource, zero disputes, zero notes and no drift
    detection for the category at all."""
    by_id = _keyed_source(tmp_path, "tf_keys_id", "acme-prod")
    by_number = _keyed_source(tmp_path, "tf_keys_number", "123456789")
    state = current(by_id, extra=(by_number,))

    mismatch = notes_of(state, drift.DRIFT_KEY_MISMATCH)
    assert len(mismatch) == 1
    assert (mismatch[0].status, mismatch[0].kind, mismatch[0].target) == (
        "unverified", drift.DRIFT_KEY_MISMATCH, "firewall_rules")
    assert by_id in mismatch[0].message and by_number in mismatch[0].message
    assert "projects/acme-prod/global/firewalls/alpha" in mismatch[0].message
    assert "projects/123456789/global/firewalls/alpha" in mismatch[0].message
    assert "zero keys matched" in mismatch[0].message

    twin = _keyed_source(tmp_path, "tf_keys_twin", "acme-prod")
    assert notes_of(current(by_id, extra=(twin,)), drift.DRIFT_KEY_MISMATCH) == []


# -- the harness ---------------------------------------------------------------


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def matrix_run(capsys, origins: str, name: str, *extra: str, as_of: str = NOW):
    return invoke(capsys, "verify-policy", str(POLICY), "--snapshot", str(ESTATE),
                  "--origins", origins,
                  "--merge-source", str(DRIFT_DIR / f"{name}.json"),
                  "--format", "json", "--no-config", "--as-of", as_of, *extra)


def state_counts(stdout: str) -> dict[str, int]:
    return dict(Counter(v["kind"] for v in json.loads(stdout)["verdicts"]
                        if v["kind"] in STATE_KINDS))


def messages(stdout: str) -> str:
    return "\n".join(v["message"] for v in json.loads(stdout)["verdicts"])


#: ``(fixture, as_of, exit code, kind → count, message substrings)``. The counts
#: cover the whole current-state family and nothing else: the policy's own
#: verdicts move with the solver backend, and every verdict this matrix mints is
#: ``unverified``, so the exit code is the policy's.
MATRIX = [
    ("tf_agree", NOW, EXIT_OK,
     {"provenance": 1, drift.DRIFT_UNMANAGED: 2},
     ["merged from 2 sources", "3 resource(s) exist in the estate"]),
    ("tf_benign", NOW, EXIT_OK,
     {"provenance": 1, drift.DRIFT_UNMANAGED: 1},
     ["merged from 2 sources"]),
    ("tf_dangerous", NOW, EXIT_OK,
     {"provenance": 1, drift.DRIFT_MATERIAL: 2, drift.DRIFT_UNMANAGED: 1},
     ["the security field 'disabled'",
      "MAY HAVE BEEN DESTROYED OR MOVED OUT OF BAND"]),
    ("tf_stale", STALE_NOW, EXIT_OK,
     {"provenance": 1, "staleness": 2, drift.DRIFT_UNMANAGED: 2},
     ["92 days before now", "past the 7 days freshness limit"]),
    ("tf_partial", NOW, EXIT_OK,
     {"provenance": 1, drift.DRIFT_UNMANAGED: 1},
     ["merged from 2 sources"]),
]


@pytest.mark.parametrize("name,as_of,code,counts,substrings", MATRIX,
                         ids=[row[0] for row in MATRIX])
def test_the_matrix_through_the_cli(capsys, api_origins, name, as_of, code,
                                    counts, substrings):
    """THE WHOLE MATRIX through ``cli.main`` in-process. ``tf_partial`` runs in
    the same two-source shape as the rest; its no-API-source contract is the
    dedicated case above, which is where "with NO API source at all" can be
    stated at all."""
    exit_code, out, _err = matrix_run(capsys, api_origins, name, as_of=as_of)
    assert exit_code == code
    assert state_counts(out) == counts
    for substring in substrings:
        assert substring in messages(out)
    # WHY THE EXIT CODE IS THE POLICY'S OWN, and why no solver branch is
    # needed: outside --drift-policy block every current-state verdict is
    # 'unverified', which report.ok ignores.
    assert {v["status"] for v in json.loads(out)["verdicts"]
            if v["kind"] in STATE_KINDS} == {"unverified"}


@pytest.mark.parametrize("policy,code", [("annotate", EXIT_OK),
                                         ("abstain", EXIT_OK),
                                         ("block", EXIT_FAILED)])
def test_the_dangerous_case_under_each_drift_policy(capsys, api_origins, policy,
                                                    code):
    """Blocking is opt-in. The identical input reports and exits 0 under
    ``annotate`` and ``abstain``, and only ``block`` turns the two material
    disagreements into gate failures."""
    exit_code, out, _err = matrix_run(capsys, api_origins, "tf_dangerous",
                                      "--drift-policy", policy)
    assert exit_code == code
    document = json.loads(out)
    material = [v for v in document["verdicts"] if v["kind"] == drift.DRIFT_MATERIAL]
    assert len(material) == 2
    expected = "contradicted" if policy == "block" else "unverified"
    assert {v["status"] for v in material} == {expected}
    assert document["summary"]["contradicted"] == (2 if policy == "block" else 0)


def test_the_agree_case_is_byte_identical_across_two_runs(capsys, api_origins):
    """CI commits a reconciled estate and reviews drift BY DIFF, so a report
    whose bytes move between runs of unchanged inputs is a report nobody can
    review."""
    first = matrix_run(capsys, api_origins, "tf_agree")[1]
    assert first == matrix_run(capsys, api_origins, "tf_agree")[1]


def test_swapping_primary_and_merge_source_yields_the_same_disputes(capsys):
    """MERGE-ORDER INDEPENDENCE, end to end rather than at the unit level.

    Which document is ``--snapshot`` and which is ``--merge-source`` is an
    invocation detail; under ``highest-fidelity-wins`` the same two views must
    produce the same disagreements either way. Both runs declare the sidecar-less
    estate ``complete`` through ``--completeness`` rather than ``--origins``,
    which reaches the primary alone and so cannot describe the swapped side.
    """
    common = ("--format", "json", "--no-config", "--completeness", "complete",
              "--as-of", NOW, "--precedence", merge.DEFAULT_PRECEDENCE)
    terraform = str(DRIFT_DIR / "tf_dangerous.json")

    def drift_lines(stdout: str):
        return sorted((v["kind"], v["target"], v["message"])
                      for v in json.loads(stdout)["verdicts"]
                      if v["kind"] in drift.DRIFT_KINDS)

    _code, api_first, _err = invoke(
        capsys, "verify-policy", str(POLICY), "--snapshot", str(ESTATE),
        "--merge-source", terraform, *common)
    _code, tf_first, _err = invoke(
        capsys, "verify-policy", str(POLICY), "--snapshot", terraform,
        "--merge-source", str(ESTATE), *common)

    lines = drift_lines(api_first)
    assert lines == drift_lines(tf_first)
    assert [kind for kind, _target, _message in lines].count(
        drift.DRIFT_MATERIAL) == 2
