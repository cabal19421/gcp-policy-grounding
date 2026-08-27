"""Acceptance for :mod:`gcp_grounding.sources` — the one current-state entry point.

The load-bearing test in this file is :func:`test_the_sidecar_loss_pin`. Every
other test here checks that a step happened; that one checks that a snapshot
copied WITHOUT its sidecar is read as ``undeclared`` and never as ``complete``,
which is the rule that keeps a terraform capture honest. Under a source-COUNT
rule it would be a single source and would read as a licensed-complete view of a
terraform-only estate: false ``baseline:new`` instead of ``baseline:unqueried``,
false ``ungrounded`` on every licensed category, and ``contradicted`` from
requires-complete widening checks.

Every test pins the clock. The committed fixtures are older than
``freshness.MAX_AGE_DEFAULT``, so an unpinned run demotes every category to
``uncaptured`` and a coverage assertion would pass for the wrong reason.
"""

from __future__ import annotations

import json
import logging
import os
import shutil

import pytest

from gcp_grounding import (
    cli,
    drift,
    estate,
    facts,
    freshness,
    merge,
    provenance,
    redact,
    sources,
)
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.provenance import SourceLedger
from gcp_grounding.reconciled import ReconciledSnapshot

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "gcp")

#: The LEGACY vocabulary-only snapshot: roles, permissions, principals,
#: constraints, resource_types and NO estate record table.
LEGACY = os.path.join(FIXTURES, "snapshot.json")
#: The estate-table shape this design introduced.
ESTATE = os.path.join(FIXTURES, "estate_snapshot.json")
#: A terraform tree, read in memory and never captured to disk.
TF_DIR = os.path.join(FIXTURES, "tf", "hcl")

#: Both committed fixtures are stamped here. Pinning the clock ON the stamp
#: keeps freshness out of every coverage assertion below.
CAPTURED_AT = "2026-07-18T09:30:00Z"
NOW = "2026-07-18T10:00:00Z"
#: Far enough past the default ceiling that every source is stale.
MUCH_LATER = "2027-07-18T10:00:00Z"


@pytest.fixture(autouse=True)
def quiet_boundary():
    """The vault and its log filter are PROCESS-WIDE. Reset both around every
    test here, and restore the ``harness`` handler set exactly, so installing
    the boundary cannot leak into the rest of the suite."""
    root = logging.getLogger(redact._HARNESS_ROOT)
    saved_handlers, saved_filters = list(root.handlers), list(root.filters)
    sources._VAULT = None
    try:
        yield
    finally:
        redact.remove_log_filter()
        root.handlers[:] = saved_handlers
        root.filters[:] = saved_filters
        sources._VAULT = None


def _copy(tmp_path, source: str, name: str = "") -> str:
    """A fixture copied OUT of the repo tree, so a sidecar cannot appear beside
    it by accident and a writer cannot dirty the checkout."""
    target = os.path.join(str(tmp_path), name or os.path.basename(source))
    if os.path.isdir(source):
        shutil.copytree(source, target)
    else:
        shutil.copyfile(source, target)
    return target


def _tree(root: str) -> set[str]:
    out = set()
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            out.add(os.path.relpath(os.path.join(dirpath, name), root))
    return out


def _kinds(state: sources.CurrentState) -> list[str]:
    return [verdict.kind for verdict in state.notes]


# -- from_env -----------------------------------------------------------------


ENV_CASES = (
    ("primary", sources.PRIMARY_ENV, "/env/snapshot.json", "/explicit/snapshot.json"),
    ("origins", sources.ORIGINS_ENV, "/env/origins.json", "/explicit/origins.json"),
    ("extra", sources.MERGE_SOURCES_ENV, "/env/a.json", ("/explicit/a.json",)),
    ("terraform_state", sources.TF_STATE_ENV, "/env/x.tfstate", ("/e/x.tfstate",)),
    ("terraform_plan", sources.TF_PLAN_ENV, "/env/plan.json", ("/e/plan.json",)),
    ("terraform_dir", sources.TF_DIR_ENV, "/env/tf", ("/e/tf",)),
    ("precedence", sources.PRECEDENCE_ENV, "terraform-wins", "api-wins"),
    ("drift_policy", sources.DRIFT_POLICY_ENV, "block", "abstain"),
    ("max_age", sources.MAX_AGE_ENV, "3d", "9d"),
    ("now", sources.NOW_ENV, CAPTURED_AT, NOW),
    ("provider_schema", sources.PROVIDER_SCHEMA_ENV, "/env/provider-schema.json",
     ("/e/provider-schema.json",)),
    ("schema_policy", sources.SCHEMA_POLICY_ENV, "annotate", "off"),
)


@pytest.mark.parametrize("field,variable,env_value,override", ENV_CASES)
def test_from_env_precedence_for_every_field(field, variable, env_value, override):
    """Env fills the field, an explicit override BEATS it, and absent in both
    leaves the field alone so the module's own default applies."""
    from_env = getattr(sources.from_env({variable: env_value}), field)
    expected = (env_value,) if field in sources.PATH_FIELDS else env_value
    assert from_env == expected, f"{variable} did not reach SourceOptions.{field}"

    overridden = getattr(sources.from_env({variable: env_value},
                                          **{field: override}), field)
    assert overridden == override, "an explicit override must beat the env var"

    absent = getattr(sources.from_env({}), field)
    assert absent == (() if field in sources.PATH_FIELDS else None), (
        "absent in env AND overrides must leave the field unset, so the "
        "module's own default applies")


def test_from_env_covers_every_field_that_has_a_variable():
    """The parametrisation above is TOTAL over :data:`sources.ENV_FIELDS`, so a
    new option with an env var cannot be added without a precedence case."""
    assert {case[0] for case in ENV_CASES} == set(sources.ENV_FIELDS)


def test_completeness_is_the_one_option_with_no_environment_variable():
    """It is the licence to read an absence as a non-existence. An exported
    variable is exactly what a shell inherits into a run nobody meant to
    license, so it is set explicitly or not at all."""
    assert "completeness" not in sources.ENV_FIELDS
    env = {"GCP_GROUNDING_COMPLETENESS": "complete"}
    assert sources.from_env(env).completeness is None
    assert sources.from_env(env, completeness="complete").completeness == "complete"


def test_the_primary_env_is_the_name_the_cli_already_uses():
    """Two names for one snapshot is two states a user can be in without
    knowing which one the gate read."""
    assert sources.PRIMARY_ENV == cli.SNAPSHOT_ENV


def test_from_env_splits_path_lists_on_the_platform_separator():
    options = sources.from_env(
        {sources.MERGE_SOURCES_ENV: os.pathsep.join(["/a.json", "/b.json"]) + os.pathsep})
    assert options.extra == ("/a.json", "/b.json"), "a trailing separator is not a path"


def test_from_env_refuses_an_unknown_override():
    with pytest.raises(TypeError, match="snapshto"):
        sources.from_env({}, snapshto="/typo.json")


def test_a_lone_string_path_is_one_path_not_its_characters():
    assert sources.SourceOptions(terraform_dir="/tf").terraform_dir == ("/tf",)


# -- the sidecar location -----------------------------------------------------


@pytest.mark.parametrize("path", ("estate.json", "/tmp/deep/estate.json",
                                  "snapshot-no-extension"))
def test_sidecar_path_agrees_with_provenance_on_three_shapes(path):
    """One definition of where the sidecar lives: the writer in ``estate.py``
    and this discovery path can never disagree."""
    assert sources.sidecar_path(path) == provenance.origins_path(path)


# -- the four-step ledger resolution ------------------------------------------


def _write_ledger(path: str, snapshot: GcpSnapshot, *, scope: str,
                  source_id: str) -> str:
    SourceLedger.unattributed(snapshot, scope=scope, source_id=source_id,
                              origin=source_id).write(path)
    return path


def test_step_one_an_explicit_origins_path_wins(tmp_path):
    snapshot_path = _copy(tmp_path, ESTATE)
    snapshot = GcpSnapshot.load(snapshot_path)
    _write_ledger(sources.sidecar_path(snapshot_path), snapshot,
                  scope="undeclared", source_id="BESIDE")
    explicit = _write_ledger(os.path.join(str(tmp_path), "elsewhere.json"),
                             snapshot, scope="partial", source_id="EXPLICIT")

    loaded, notes = sources.load_source(snapshot_path, origins=explicit)

    assert notes == ()
    assert list(loaded.ledger.sources) == ["EXPLICIT"]


def test_step_two_a_present_sidecar_beats_the_unattributed_fallback(tmp_path):
    snapshot_path = _copy(tmp_path, ESTATE)
    snapshot = GcpSnapshot.load(snapshot_path)
    _write_ledger(sources.sidecar_path(snapshot_path), snapshot,
                  scope="partial", source_id="BESIDE")

    loaded, notes = sources.load_source(snapshot_path)

    assert notes == ()
    assert list(loaded.ledger.sources) == ["BESIDE"]
    assert loaded.ledger.scope_of("firewall_rules").scope == "partial"


def test_step_three_the_declared_scope_is_used_when_no_ledger_exists(tmp_path):
    snapshot_path = _copy(tmp_path, ESTATE)

    loaded, _notes = sources.load_source(snapshot_path, completeness="partial")

    assert list(loaded.ledger.sources) == [snapshot_path]
    assert loaded.ledger.scope_of("firewall_rules").scope == "partial"


def test_step_four_falls_back_to_the_shape_default(tmp_path):
    snapshot_path = _copy(tmp_path, ESTATE)

    loaded, _notes = sources.load_source(snapshot_path)

    assert loaded.ledger.scope_of("firewall_rules").scope == "undeclared"
    # The merged record carries NO note. It used to say "<kind> source loaded
    # in memory" — true of every source in the list, so it distinguished
    # nothing while every explain surface printed it under the source line,
    # crowding out the notes that do (the terraform 'partial' cap, the state
    # serial and lineage). The kind and the origin that sentence restated are
    # the line's own first two columns.
    record = loaded.record()
    assert record.note == ""
    assert record.origin == snapshot_path and record.kind


def test_a_corrupt_sidecar_falls_back_with_a_verdict_and_never_to_complete(tmp_path):
    """A broken sidecar must never make a usable snapshot unusable, and must
    never silently promote it to ``complete``."""
    snapshot_path = _copy(tmp_path, ESTATE)
    sidecar = sources.sidecar_path(snapshot_path)
    with open(sidecar, "w", encoding="utf-8") as handle:
        handle.write("{ this is not json")

    loaded, notes = sources.load_source(snapshot_path)

    assert loaded is not None, "the snapshot itself is still perfectly usable"
    assert [note.kind for note in notes] == ["provenance"]
    assert sidecar in notes[0].message
    assert loaded.ledger.scope_of("firewall_rules").scope == "undeclared"
    assert loaded.ledger.scope_of("firewall_rules").scope != "complete"


def test_a_missing_sidecar_is_silent_on_a_single_source_run(tmp_path):
    """A note on every single-source run would train users to ignore the
    channel."""
    loaded, notes = sources.load_source(_copy(tmp_path, ESTATE), multi=False)
    assert notes == () and loaded is not None

    _loaded, multi_notes = sources.load_source(_copy(tmp_path, ESTATE, "second.json"),
                                               multi=True)
    assert [note.kind for note in multi_notes] == ["provenance"]


# -- THE SIDECAR-LOSS PIN -----------------------------------------------------


def test_the_sidecar_loss_pin(tmp_path):
    """A snapshot carrying an estate record table, loaded as the ONLY source
    with NO sidecar, falls back to ``undeclared`` and NOT to ``complete``.

    Source COUNT is the wrong discriminator: a terraform capture copied without
    its sidecar is a SINGLE source, and reading it as complete licenses a
    negative about every resource terraform does not manage.
    """
    snapshot_path = _copy(tmp_path, ESTATE)
    assert not os.path.exists(sources.sidecar_path(snapshot_path))
    options = sources.SourceOptions(primary=snapshot_path, now=NOW)

    state = sources.load_current(options)

    assert state.ok and state.sources == (snapshot_path,), "ONE source, loaded"
    assert sources.has_estate_table(state.snapshot)
    covered = state.ledger.declared_categories()
    assert covered, "the fallback ledger must declare what the snapshot captured"
    for category in covered:
        scope = state.ledger.scope_of(category)
        assert scope.scope == "undeclared", (
            f"{category} fell back to {scope.scope!r}; an estate-table snapshot "
            f"with no sidecar is never licensed-complete")
        reason = state.snapshot.require_complete(category)
        assert reason is not None and "undeclared" in reason, (
            f"absence in {category} must not be readable as non-existence")

    # ...and saying so explicitly is the ONLY thing that changes it.
    licensed = sources.load_current(
        sources.SourceOptions(primary=snapshot_path, now=NOW,
                              completeness="complete"))
    for category in covered:
        assert licensed.ledger.scope_of(category).scope == "complete"
        assert licensed.snapshot.require_complete(category) is None


def test_the_legacy_vocabulary_only_shape_still_falls_back_to_complete(tmp_path):
    """Same single-source position, other shape: no estate record table means
    the legacy default, which reproduces today's behaviour exactly."""
    snapshot_path = _copy(tmp_path, LEGACY)
    assert not sources.has_estate_table(GcpSnapshot.load(snapshot_path))

    state = sources.load_current(sources.SourceOptions(primary=snapshot_path, now=NOW))

    assert sources.default_completeness(state.snapshot) == "complete"
    assert state.ledger.scope_of("roles").scope == "complete"
    assert state.snapshot.require_complete("roles") is None


def test_the_legacy_pin_covers_zero_estate_domains():
    """The COMMITTED legacy fixture, whose categories contain no estate table,
    yields a current state covering ZERO estate domains — so a user who upgrades
    without recapturing gets honest ``unqueried`` everywhere and never a false
    clean bill of health."""
    state = sources.load_current(sources.SourceOptions(primary=LEGACY, now=NOW))

    assert state.ok
    for category in sources.ESTATE_TABLES:
        assert getattr(state.snapshot, category) is None, (
            f"{category} is an estate domain the legacy fixture never captured")
        assert state.snapshot.require_complete(category) is not None, (
            f"{category} was never captured, so nothing may be concluded from "
            f"its absence")
    assert state.ledger.scope_of("firewall_rules").scope == "uncaptured"


# -- terraform as an in-memory source -----------------------------------------


def test_a_terraform_directory_contributes_facts_without_writing_anything(tmp_path):
    tree = _copy(tmp_path, TF_DIR, "tf")
    before = _tree(str(tmp_path))
    options = sources.SourceOptions(primary=ESTATE, terraform_dir=(tree,), now=NOW)

    state = sources.load_current(options)

    assert state.ok and state.reconciled
    assert _tree(str(tmp_path)) == before, "no capture file may be written"
    tf_only = "projects/acme-prod/global/firewalls/allow-ssh-world"
    assert tf_only not in (GcpSnapshot.load(ESTATE).firewall_rules or {})
    assert tf_only in state.snapshot.firewall_rules, (
        "the terraform tree must contribute facts to the merged current state")
    assert state.ledger.scope_of("firewall_rules").scope == "partial"
    assert "hcl" in state.ledger.scope_of("firewall_rules").source_kinds


def test_the_merge_keeps_the_vocabularies_no_fact_can_carry(tmp_path):
    """``facts.Fact`` refuses the four platform vocabularies, so a merged view
    would LOSE them without the carry-over."""
    tree = _copy(tmp_path, TF_DIR, "tf")
    state = sources.load_current(sources.SourceOptions(
        primary=ESTATE, terraform_dir=(tree,), now=NOW))

    primary = GcpSnapshot.load(ESTATE)
    for category in sources.CARRIED_CATEGORIES:
        assert category in facts.EXCLUDED_CATEGORIES
        assert getattr(state.snapshot, category) == getattr(primary, category)


# -- the fixed note order -----------------------------------------------------


def test_notes_come_back_provenance_then_staleness_then_drift(tmp_path):
    tree = _copy(tmp_path, TF_DIR, "tf")
    state = sources.load_current(sources.SourceOptions(
        primary=ESTATE, terraform_dir=(tree,), now=MUCH_LATER))

    # The order is spelled OUT here rather than read from sources.NOTE_ORDER:
    # sorting by the constant under test would make this assertion true for any
    # order the module happened to declare.
    order = ("provenance", "staleness", "drift")
    assert sources.NOTE_ORDER == order
    families = [sources.note_family(kind) for kind in _kinds(state)]
    assert set(families) == set(order), (
        f"this fixture must exercise all three families, got {_kinds(state)}")
    assert families == sorted(families, key=order.index), (
        "report output is only stable if the note order is fixed")
    assert any(v.target == "current-state" and v.kind == "provenance"
               for v in state.notes), "the multi-source note must be emitted"
    note = next(v for v in state.notes if v.target == "current-state")
    assert tree in note.message and ESTATE in note.message
    assert CAPTURED_AT in note.message, "each source's capture time is listed"


def test_the_note_order_is_total_over_the_kinds_this_module_routes():
    for kind in (sources.PROVENANCE_KINDS + freshness.STALENESS_KINDS
                 + drift.DRIFT_KINDS):
        assert sources.note_family(kind) in sources.NOTE_ORDER


# -- the fail-open contract ---------------------------------------------------


def test_a_raising_merge_returns_the_unreconciled_primary(tmp_path, monkeypatch):
    second = _copy(tmp_path, ESTATE, "second.json")
    options = sources.SourceOptions(primary=ESTATE, extra=(second,), now=NOW)

    def boom(*args, **kwargs):
        raise RuntimeError("merge is broken today")

    monkeypatch.setattr(merge, "resolve", boom)
    state = sources.load_current(options)

    assert state.snapshot is not None, "a merge bug may not take down the gate"
    assert state.reconciled is False
    assert isinstance(state.snapshot, ReconciledSnapshot)
    assert state.snapshot == GcpSnapshot.load(ESTATE), "the PRIMARY, untouched"
    step = [v for v in state.notes if v.target == "step:merge"]
    assert len(step) == 1 and step[0].kind == "provenance"
    assert step[0].status == "unverified"
    assert "RuntimeError" in step[0].message and "UNRECONCILED" in step[0].message


def test_a_missing_extra_source_is_one_state_source_verdict(tmp_path):
    missing = os.path.join(str(tmp_path), "absent.json")
    state = sources.load_current(sources.SourceOptions(
        primary=ESTATE, extra=(missing,), now=NOW))

    assert state.ok, "the run still returns a snapshot"
    failed = [v for v in state.notes if v.kind == "state:source"]
    assert len(failed) == 1
    assert failed[0].target == missing and failed[0].status == "unverified"
    assert "contributed NOTHING" in failed[0].message
    assert state.sources == (ESTATE,)


def test_a_failing_terraform_source_is_one_state_source_verdict(tmp_path):
    empty = os.path.join(str(tmp_path), "empty")
    os.mkdir(empty)
    state = sources.load_current(sources.SourceOptions(
        primary=ESTATE, terraform_dir=(empty,), now=NOW))

    assert state.ok
    failed = [v for v in state.notes if v.kind == "state:source"]
    assert len(failed) == 1 and failed[0].target == empty


def test_zero_sources_returns_empty_and_silent():
    state = sources.load_current(sources.SourceOptions(now=NOW))

    assert state.snapshot is None and state.ledger is None
    assert state.notes == () and state.problem == "" and state.sources == ()
    assert state.ok is False, "there is no current state, but nothing failed"


@pytest.mark.parametrize("options,token,flag", (
    (sources.SourceOptions(primary=ESTATE, precedence="terraform-winz"),
     "terraform-winz", "--precedence"),
    (sources.SourceOptions(primary=ESTATE, drift_policy="anotate"),
     "anotate", "--drift-policy"),
    (sources.SourceOptions(primary=ESTATE, max_age="7dd"), "7dd", "--max-age"),
    (sources.SourceOptions(primary=ESTATE, completeness="compleet"),
     "compleet", "--completeness"),
))
def test_a_malformed_option_is_a_usage_problem_naming_the_token(options, token, flag):
    """A typo must not silently fall back to a default and change what the gate
    enforces."""
    state = sources.load_current(options)

    assert token in state.problem and flag in state.problem
    assert state.snapshot is None and state.notes == (), "it grounds nothing"


def test_a_valid_precedence_reaches_the_reconciled_snapshot(tmp_path):
    second = _copy(tmp_path, ESTATE, "second.json")
    state = sources.load_current(sources.SourceOptions(
        primary=ESTATE, extra=(second,), precedence="terraform-wins", now=NOW))

    assert state.problem == ""
    assert state.snapshot.policy_name == "terraform-wins"


# -- the one secret boundary --------------------------------------------------


def test_the_log_filter_is_installed_exactly_once_across_two_calls(monkeypatch):
    calls: list[redact.SecretVault] = []
    real = redact.install_log_filter

    def counted(vault):
        calls.append(vault)
        return real(vault)

    monkeypatch.setattr(redact, "install_log_filter", counted)
    options = sources.SourceOptions(primary=ESTATE, now=NOW)

    first = sources.load_current(options)
    second = sources.load_current(options)

    assert first.ok and second.ok
    assert len(calls) == 1, ("the process-wide vault installs the log filter "
                             "ONCE; re-installing per call would rebuild the "
                             "boundary under a live handler set")
    assert calls[0] is sources.vault()


def test_write_reconciled_uses_the_same_two_writers(tmp_path):
    state = sources.load_current(sources.SourceOptions(primary=ESTATE, now=NOW))
    target = os.path.join(str(tmp_path), "reconciled.json")

    snapshot_path, ledger_path = sources.write_reconciled(state, target)

    assert (snapshot_path, ledger_path) == (target, sources.sidecar_path(target))
    with open(snapshot_path, encoding="utf-8") as handle:
        text = handle.read()
    assert text.endswith("}\n"), "fetch.write_snapshot's format, reused"
    assert json.loads(text)["captured_at"] == CAPTURED_AT
    assert SourceLedger.load(ledger_path).declared_categories()


def test_write_reconciled_refuses_an_empty_state():
    with pytest.raises(ValueError, match="no current state"):
        sources.write_reconciled(sources.CurrentState(), "/tmp/never-written.json")


def test_the_estate_tables_are_read_from_the_model_that_defines_them():
    """A record table added to the snapshot model must not need an edit here to
    be recognised: a table this module does not know about is a table whose
    absence gets licensed by accident."""
    assert set(sources.ESTATE_TABLES) <= set(provenance.CATEGORIES)
    assert "firewall_rules" in sources.ESTATE_TABLES
    assert "roles" not in sources.ESTATE_TABLES, (
        "roles is a legacy vocabulary, not an estate record table — the legacy "
        "fixture carries one and must still default to 'complete'")


def test_snapshot_facts_is_an_adapter_and_adds_nothing():
    snapshot = GcpSnapshot.load(ESTATE)
    adapted = sources.snapshot_facts(snapshot, source="api", origin=ESTATE)

    assert {fact.category for fact in adapted} <= set(facts.TF_CATEGORIES)
    for category in facts.EXCLUDED_CATEGORIES:
        assert all(fact.category != category for fact in adapted)
    rows = sum(len(getattr(snapshot, c) or ())
               for c in facts.TF_CATEGORIES if getattr(snapshot, c) is not None)
    assert len(adapted) == rows, "every row, exactly once"


def test_estate_capture_and_this_module_agree_on_the_sidecar(tmp_path):
    """The writer and this discovery path resolve the same file."""
    captured = estate.capture(TF_DIR)
    target = os.path.join(str(tmp_path), "capture.json")
    _snapshot_path, ledger_path = estate.write_capture(captured, target)
    assert ledger_path == sources.sidecar_path(target)

    loaded, notes = sources.load_source(target)
    assert notes == (), "the sidecar the writer just wrote is found, not guessed"
    assert loaded.ledger.scope_of("firewall_rules").scope == "partial"
