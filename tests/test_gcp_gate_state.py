"""Acceptance for the gate's CURRENT-STATE input — where the headline win lands.

Everything here runs IN-PROCESS. Capability is branched on with plain
module-level booleans (the ``HAVE_Z3`` idiom) and never ``skipif``, so an absent
capability is asserted to degrade honestly rather than being quietly passed over.

The load-bearing tests, and the failure each one guards:

- :func:`test_nothing_configured_is_byte_identical_to_the_un_edited_document` —
  THE ZERO-CHANGE GUARANTEE. The golden is rebuilt here from
  ``preflight.ground_policy`` plus the pre-existing document shape, so it is an
  independent statement of what today's gate emits rather than a snapshot of
  what the edited one happens to produce.
- :func:`test_a_configured_state_source_adds_only_the_state_key` — the schema
  claim. ``GATE_SCHEMA`` is not bumped, so a consumer pinned to it must never
  receive a differently SHAPED document under the same version: exactly one key
  is added, and only when a state source was configured.
- :func:`test_a_widened_policy_fails_against_the_current_view_with_no_flag` and
  :func:`test_a_partial_view_downgrades_the_widening_to_an_unverified` — the
  point of the whole input. ``constraints.check_policy_subset`` is the one thing
  in the repo that can say "this change grants something the old policy did
  not", and before this it only ran when a human typed ``--baseline``. The
  second half is the partial-baseline asymmetry arriving through the gate.
- :func:`test_a_capped_drift_list_still_surfaces_every_kind` — the pair that
  neither task can assert alone. ``ALWAYS_REPORT_KINDS`` promises every drift
  kind reaches the operator; ``drift.MAX_DRIFT_VERDICTS`` caps the list. A naive
  head-truncation satisfies the cap and breaks the promise, so the two are
  asserted TOGETHER.
- :func:`test_omitting_as_of_still_evaluates_staleness` — the fail-open hole
  this input exists to close. The PostToolUse hook is invoked with one fixed
  command line, so an omitted ``as_of`` that meant "never check staleness" would
  treat a six-month-old auto-discovered ``terraform.tfstate`` as current forever.
- :func:`test_discovery_resolves_a_different_config_per_edited_file` — a hook
  command line can pin exactly ONE baseline for a whole session; an agent
  editing two modules needs two, and gets them from the state discovered beside
  each file.
- :func:`test_a_merged_disagreement_is_noted_once_across_a_three_file_set` —
  source notes are estate-wide, so a copy per file would multiply them by the
  changed-file count and inflate every count that reads them.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path

import pytest

from gcp_grounding import (baseline, discovery, drift, engine, freshness, gate,
                           preflight, provenance, redact, sources)
from gcp_grounding.core.report import Verdict
from gcp_grounding.core.solver import get_solver
from gcp_grounding.gate import (ALWAYS_REPORT_KINDS, GATE_SCHEMA,
                                PolicyGroundingGate)
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.provenance import Dispute, LedgerBuilder
from gcp_grounding.reconciled import ReconciledSnapshot
from gcp_grounding.report import PolicyReport

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
SNAPSHOT = FIXTURES / "snapshot.json"
ESTATE = FIXTURES / "estate_snapshot.json"

CAPTURED = "2026-07-18T09:30:00Z"          # every fixture snapshot's captured_at
FRESH = "2026-07-20T09:30:00Z"             # two days later: inside the ceiling
STALE = "2026-07-26T09:30:01Z"             # eight days later: past the ceiling

IAM_KEY = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
FW_KEY = "projects/acme-prod/global/firewalls/allow-iap-ssh"

#: The four committed policy fixtures, in a fixed order.
COMMITTED = ("iam_policy_good.json", "iam_policy_bad.json",
             "org_policy_good.json", "org_policy_bad.json")

HAVE_Z3 = get_solver().backend == "z3"

SECRET = "GATE-STATE-CANARY-6b41f0d2-not-a-real-secret"


# -- isolation ----------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_boundary(monkeypatch):
    """A FRESH process vault and log filter per test, restored exactly.

    The gate installs the secret boundary as a side effect of scrubbing a
    report, and neither the vault nor the handler set may leak into the rest of
    the suite: a canary left in the process vault would scrub a later module's
    output.
    """
    root = logging.getLogger(redact._HARNESS_ROOT)
    saved_handlers = list(root.handlers)
    saved_filters = {handler: list(handler.filters) for handler in saved_handlers}
    monkeypatch.setattr(sources, "_VAULT", None)
    monkeypatch.setattr(redact, "_INSTALLED", None)
    monkeypatch.setattr(redact, "_OWNED_HANDLER", None)
    monkeypatch.delenv(freshness.NOW_ENV, raising=False)
    monkeypatch.delenv(discovery.CONFIG_ENV, raising=False)
    try:
        yield
    finally:
        redact.remove_log_filter()
        for handler in list(root.handlers):
            if handler not in saved_handlers:
                root.removeHandler(handler)
        root.handlers[:] = saved_handlers
        for handler, filters in saved_filters.items():
            handler.filters[:] = filters


# -- helpers ------------------------------------------------------------------


def committed(*names: str) -> list[Path]:
    return [POLICIES / name for name in (names or COMMITTED)]


def golden_document(paths) -> dict:
    """Today's gate document for *paths*, rebuilt from the UN-EDITED code path.

    Every one of these files is a policy candidate that
    ``preflight.ground_policy`` judges end to end, so the routing is the only
    thing hardcoded; the statuses, the risk grading, the findings and the
    per-file report documents are all derived exactly as the pre-existing gate
    derived them. The schema string is written out literally, which is also the
    pin that this document's promise not to bump it was kept.
    """
    snapshot = GcpSnapshot.load(SNAPSHOT)
    entries: list[dict] = []
    findings: list[str] = []
    counts = {"ok": 0, "unverified": 0, "failed": 0}
    for path in paths:
        report = preflight.ground_policy(str(path), snapshot)
        if not report.ok:
            status = "failed"
        elif report.verdicts and all(v.status == "unverified"
                                     for v in report.verdicts):
            status = "unverified"
        else:
            status = "ok"
        counts[status] += 1
        entries.append({
            "path": str(path),
            "status": status,
            "policy_candidate": True,
            "report": PolicyReport(report, snapshot.captured_at,
                                   source=str(path)).to_dict(),
        })
        for verdict in report.verdicts:
            if verdict.status in ("ungrounded", "contradicted"):
                tip = (f" (did you mean: {', '.join(verdict.suggestions)}?)"
                       if verdict.suggestions else "")
                findings.append(f"{path}: {verdict.status} {verdict.kind} — "
                                f"{verdict.message}{tip}")
        if status == "unverified":
            for verdict in report.verdicts:
                findings.append(f"{path}: unverified — {verdict.message}")
    ok = all(entry["status"] != "failed" for entry in entries)
    if not ok:
        risk = "high"
    elif any(entry["status"] == "unverified" for entry in entries):
        risk = "low"
    else:
        risk = "none"
    return {
        "schema": "gcp-grounding-gate/1",
        "ok": ok,
        "risk": risk,
        "backend": get_solver().backend,
        "captured_at": snapshot.captured_at,
        "counts": counts,
        "files": entries,
        "findings": findings,
    }


def estate_state(*, completeness: str = "complete", now: str = FRESH,
                 primary: Path = ESTATE, extra: tuple[str, ...] = ()
                 ) -> sources.CurrentState:
    """The fixture estate as an assembled current state."""
    return sources.load_current(sources.SourceOptions(
        primary=str(primary), extra=extra, completeness=completeness, now=now))


def terraform_state(*, now: str = FRESH) -> sources.CurrentState:
    """The fixture vocabulary plus the fixture TERRAFORM STATE as a second
    source — the partial current-state view this whole design exists for."""
    return sources.load_current(sources.SourceOptions(
        primary=str(ESTATE),
        terraform_state=(str(FIXTURES / "tf" / "estate.tfstate"),), now=now))


def iam_settings(path, *, key: str = IAM_KEY, requirements: str = ""
                 ) -> discovery.Settings:
    """Settings whose target map points *path* at an estate IAM row — the only
    way a document that does not name its own resource acquires a baseline."""
    return discovery.Settings(
        targets={str(path): baseline.TargetRef(category="iam_bindings", key=key,
                                               how=discovery.TARGET_HOW)},
        requirements=requirements)


def policy_file(directory: Path, name: str, bindings) -> Path:
    path = directory / name
    path.write_text(json.dumps({"bindings": bindings}), encoding="utf-8")
    return path


#: The estate's own bindings for :data:`IAM_KEY`, as an IAM allow policy.
CURRENT_BINDINGS = [
    {"role": "roles/owner", "members": ["user:alice@acme.example"]},
    {"role": "roles/iam.securityAdmin",
     "members": ["serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com"]},
]

#: The same, plus one member the current policy does not grant.
WIDENED_BINDINGS = [
    {"role": "roles/owner", "members": ["user:alice@acme.example"]},
    {"role": "roles/iam.securityAdmin",
     "members": ["serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com",
                 "group:data-eng@acme.example"]},
]


def kinds_of(result) -> list[str]:
    return [v.kind for f in result.files for v in f.verdicts]


# -- the zero-change guarantee ------------------------------------------------


def test_nothing_configured_is_byte_identical_to_the_un_edited_document():
    """With no current, no discovery and no source resolution the document is
    today's, key for key and value for value — no extra key of ANY kind."""
    changed = committed()
    document = PolicyGroundingGate(SNAPSHOT).check(changed).to_dict()
    expected = golden_document(changed)
    assert list(document) == list(expected)
    assert document == expected
    assert document["schema"] == GATE_SCHEMA == "gcp-grounding-gate/1"
    for entry in document["files"]:
        assert list(entry) == ["path", "status", "policy_candidate", "report"]
        assert "state" not in entry
    json.dumps(document)


def test_the_per_file_result_carries_no_state_rows_without_a_source():
    result = PolicyGroundingGate(SNAPSHOT).check(committed("org_policy_good.json"))
    assert result.state_configured is False
    assert result.state == ()
    assert all(f.state == () for f in result.files)
    # A clean run stays byte-quiet: no state block is appended to the render.
    assert "state used this run" not in result.render()


def test_a_configured_state_source_adds_only_the_state_key():
    """The schema claim, asserted on SHAPE: exactly one key is added, at the
    top level and per file, and every pre-existing key keeps its place."""
    changed = committed()
    expected = golden_document(changed)
    gated = PolicyGroundingGate(SNAPSHOT, current=estate_state())
    document = gated.check(changed, as_of=FRESH).to_dict()
    assert set(document) - set(expected) == {"state"}
    assert [key for key in document if key != "state"] == list(expected)
    for entry in document["files"]:
        assert [key for key in entry if key != "state"] == [
            "path", "status", "policy_candidate", "report"]
        assert isinstance(entry["state"], list)
    assert document["state"] == [row for entry in document["files"]
                                 for row in entry["state"]]
    json.dumps(document)


def test_the_render_appends_the_state_block_only_when_a_source_was_configured():
    gated = PolicyGroundingGate(SNAPSHOT, current=estate_state())
    rendered = gated.check(committed("iam_policy_good.json"), as_of=FRESH).render()
    assert "state used this run" in rendered
    assert "GCP policy gate" in rendered.splitlines()[0]


# -- the pair checks the agentic path could never reach -----------------------


def test_a_widened_policy_fails_against_the_current_view_with_no_flag(tmp_path):
    """The headline win: no ``--baseline`` is typed anywhere and the widening
    is still caught, because the CURRENT state supplied the counterpart."""
    path = policy_file(tmp_path, "widened.policy.json", WIDENED_BINDINGS)
    gated = PolicyGroundingGate(SNAPSHOT, current=estate_state(),
                                settings=iam_settings(path))
    result = gated.check([path], as_of=FRESH)
    assert not result.ok and result.risk == "high"
    assert [f.status for f in result.files] == ["failed"]
    text = "\n".join(result.findings())
    assert "new⊈old" in text and "group:data-eng@acme.example" in text
    # No baseline flag exists on this API at all — the counterpart came from
    # the configured current state and from nothing the caller typed.
    assert not any(v.kind.startswith("baseline:") for v in result.files[0].verdicts)


def test_a_partial_view_downgrades_the_widening_to_an_unverified(tmp_path):
    """THE PARTIAL-BASELINE ASYMMETRY, arriving through the gate: a terraform
    view covers only what terraform manages, so its ``contradicted`` may be a
    phantom and is rewritten to an ``unverified`` NAMING the partial source.

    The view here is a REAL terraform state, which is structurally at most
    ``partial`` — the scope is never declared by this test.
    """
    path = policy_file(tmp_path, "widened.policy.json", WIDENED_BINDINGS)
    state = terraform_state()
    assert state.ledger.scope_of("iam_bindings").scope == "partial"
    gated = PolicyGroundingGate(SNAPSHOT, current=state,
                                settings=iam_settings(path))
    result = gated.check([path], as_of=FRESH)
    assert result.ok and [f.status for f in result.files] == ["ok"]
    [subset] = [v for v in result.files[0].verdicts if v.kind == "subset"]
    assert subset.status == "unverified"
    assert "partial" in subset.message and "new⊈old" in subset.message


def test_a_reconciled_snapshot_constructs_and_grounds_normally():
    """``ReconciledSnapshot`` SUBCLASSES ``GcpSnapshot``, which is why the
    isinstance path needs no flag: it is accepted, ``resolve_sources`` is
    ignored for it, and there are no source notes to carry."""
    state = estate_state()
    assert isinstance(state.snapshot, ReconciledSnapshot)
    gated = PolicyGroundingGate(state.snapshot, resolve_sources=True)
    assert gated.snapshot is state.snapshot
    assert gated.source_notes == ()
    assert gated.state_configured is False
    result = gated.check(committed("org_policy_good.json"))
    assert result.ok and [f.status for f in result.files] == ["ok"]
    assert result.captured_at == CAPTURED


# -- drift visibility ---------------------------------------------------------


def drifting_state(*notes: Verdict) -> sources.CurrentState:
    state = estate_state()
    return dataclasses.replace(state, notes=tuple(state.notes) + notes)


def test_a_drift_verdict_shows_on_an_otherwise_clean_file(tmp_path):
    """Today's findings helper surfaces unverified notes only when the WHOLE
    file is unverified, so a file with one ok verdict and one drift verdict
    shows the agent nothing at all."""
    path = policy_file(tmp_path, "same.policy.json", CURRENT_BINDINGS)
    note = Verdict("unverified", drift.DRIFT_MATERIAL, f"firewall_rules/{FW_KEY}", 0,
                   "the sources disagree about the security field 'source_ranges'")
    gated = PolicyGroundingGate(SNAPSHOT, current=drifting_state(note),
                                settings=iam_settings(path))
    result = gated.check([path], as_of=FRESH)
    [file] = result.files
    assert file.status == "ok" and result.ok is True
    assert any(v.status == "grounded" for v in file.verdicts)
    assert result.risk == "low"           # raised to low, NEVER to high
    findings = result.findings()
    assert [line for line in findings if "source_ranges" in line]
    assert all(line.startswith(str(path) + ": ") for line in findings)


def test_an_always_reported_line_is_never_printed_twice(tmp_path):
    """The dedup against the wholly-unverified pass: a file that is entirely
    unverified must not print its drift line once for each pass."""
    empty = tmp_path / "empty.policy.json"
    empty.write_text(json.dumps({"etag": "BwX=", "version": 3}), encoding="utf-8")
    note = Verdict("unverified", drift.DRIFT_UNMANAGED, "firewall_rules", 0,
                   "4 resource(s) exist in the estate and are absent from terraform")
    gated = PolicyGroundingGate(SNAPSHOT, current=drifting_state(note))
    result = gated.check([empty], as_of=FRESH)
    [file] = result.files
    assert file.status == "unverified"
    matching = [line for line in result.findings()
                if "absent from terraform" in line]
    assert len(matching) == 1


def test_a_capped_drift_list_still_surfaces_every_kind():
    """THE PAIR, asserted together because neither half is enough alone.

    ``ALWAYS_REPORT_KINDS`` promises every drift kind reaches the operator even
    on an otherwise clean file; ``drift.MAX_DRIFT_VERDICTS`` caps the list. A
    naive head-truncation of a sorted list satisfies the cap and silently
    breaks the promise, which is why ``drift.py`` fills its budget round-robin
    and never drops the first verdict of any kind.
    """
    assert set(drift.DRIFT_KINDS) <= set(ALWAYS_REPORT_KINDS)

    builder = LedgerBuilder()
    builder.source("api-capture", "api", origin="<fetch>", captured_at=CAPTURED,
                   scope="complete")
    builder.declare("firewall_rules", scope="complete", source_kinds=("api",))
    over = drift.MAX_DRIFT_VERDICTS + 20
    for index in range(over):
        builder.dispute(Dispute(category="firewall_rules",
                                key=f"projects/acme-prod/global/firewalls/r{index:03d}",
                                field="source_ranges", severity="material",
                                left="10.0.0.0/8", right="0.0.0.0/0",
                                reason="the two views differ"))
    # EXACTLY ONE verdict of a rare kind, sorted last among the material ones.
    builder.dispute(Dispute(category="firewall_rules", key="zzz-unmanaged",
                            severity="unmanaged", left="api-capture",
                            right="/repo/terraform.tfstate",
                            reason="not managed by terraform"))
    ledger = builder.build()
    capped = drift.drift_verdicts(ledger, policy="annotate")
    assert len(capped) <= drift.MAX_DRIFT_VERDICTS + 1      # + the summary
    rare = [v for v in capped if v.kind == drift.DRIFT_UNMANAGED]
    assert len(rare) == 1, "the cap dropped the only verdict of a rare kind"

    snapshot = ReconciledSnapshot.from_snapshot(GcpSnapshot.load(ESTATE),
                                                ledger=ledger)
    state = sources.CurrentState(snapshot=snapshot, ledger=ledger,
                                 notes=capped, reconciled=True)
    result = PolicyGroundingGate(SNAPSHOT, current=state).check(
        committed("org_policy_good.json"), as_of=FRESH)
    surfaced = "\n".join(result.findings())
    assert rare[0].message in surfaced
    assert result.ok is True and result.risk == "low"


# -- per-file config discovery ------------------------------------------------


def write_config(directory: Path, snapshot: Path, target_path: Path, *,
                 max_age: str | None = None) -> Path:
    document = {
        "schema": discovery.CONFIG_SCHEMA,
        "snapshot": str(snapshot),
        "targets": {str(target_path): f"iam_bindings:{IAM_KEY}"},
    }
    if max_age is not None:
        document["max_age"] = max_age
    path = directory / discovery.CONFIG_NAMES[0]
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def widened_estate(tmp_path: Path) -> Path:
    """A second estate snapshot whose IAM row ALREADY grants the wider set, so
    the same proposal is a widening against one view and not against the other."""
    payload = json.loads(ESTATE.read_text(encoding="utf-8"))
    payload["iam_bindings"][IAM_KEY] = {"bindings": WIDENED_BINDINGS}
    path = tmp_path / "wide_snapshot.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def two_repos(tmp_path: Path) -> tuple[Path, Path]:
    """Two directories under one repo marker, each with its own config."""
    (tmp_path / ".git").write_text("", encoding="utf-8")
    narrow, wide = tmp_path / "narrow", tmp_path / "wide"
    narrow.mkdir()
    wide.mkdir()
    first = policy_file(narrow, "a.policy.json", WIDENED_BINDINGS)
    second = policy_file(wide, "b.policy.json", WIDENED_BINDINGS)
    write_config(narrow, ESTATE, first)
    write_config(wide, widened_estate(tmp_path), second)
    return first, second


def test_discovery_resolves_a_different_config_per_edited_file(tmp_path):
    """A hook command line is one fixed string and can pin exactly ONE
    baseline for a whole session. Two files under two configs get two."""
    first, second = two_repos(tmp_path)
    gated = PolicyGroundingGate(
        SNAPSHOT, discover_config=True,
        options=sources.SourceOptions(completeness="complete"))
    result = gated.check([first, second], as_of=FRESH)
    narrow_file, wide_file = result.files
    assert narrow_file.status == "failed"      # widening against the narrow view
    assert wide_file.status == "ok"            # already granted in the wide view
    assert not result.ok and result.risk == "high"
    # Two files, two DIFFERENT baselines, one check call.
    def source_of(file_result):
        return [row["source"] for row in file_result.state
                if row["row"] == "sources"]
    assert source_of(narrow_file) != source_of(wide_file)
    assert source_of(narrow_file) == [str(ESTATE)]


def test_the_config_load_happens_once_per_directory(tmp_path, monkeypatch):
    """Caching is by resolved CONFIG DIRECTORY, so a ten-file diff in one repo
    does one load while a file under a second config still gets its own."""
    first, second = two_repos(tmp_path)
    nested = first.parent / "nested"
    nested.mkdir()
    third = policy_file(nested, "c.policy.json", CURRENT_BINDINGS)

    calls: list = []
    real = sources.load_current

    def counting(options):
        calls.append(options)
        return real(options)

    monkeypatch.setattr(sources, "load_current", counting)
    gated = PolicyGroundingGate(
        SNAPSHOT, discover_config=True,
        options=sources.SourceOptions(completeness="complete"))
    result = gated.check([first, third, second], as_of=FRESH)
    assert len(result.files) == 3
    # `first` and `third` are governed by the SAME config: two loads, not three.
    assert len(calls) == 2
    # The clock resolved ONCE at the gate boundary is threaded into every load.
    pinned = freshness.resolve_now(FRESH)
    assert all(freshness.parse_timestamp(options.now) == pinned
               for options in calls)


# -- the clock ----------------------------------------------------------------


def stale_repo(tmp_path: Path, *, max_age: str | None = None) -> Path:
    (tmp_path / ".git").write_text("", encoding="utf-8")
    path = policy_file(tmp_path, "a.policy.json", CURRENT_BINDINGS)
    write_config(tmp_path, ESTATE, path, max_age=max_age)
    return path


def stale_kinds(result) -> list[str]:
    return [k for k in kinds_of(result) if k == "baseline:stale"]


def test_threading_an_as_of_makes_a_stale_view_say_so(tmp_path, monkeypatch):
    """The clock the CALLER pins wins over the environment's, which is what
    makes ``as_of`` a real input rather than a re-spelling of the env var."""
    monkeypatch.setenv(freshness.NOW_ENV, FRESH)
    path = stale_repo(tmp_path)
    gated = PolicyGroundingGate(
        SNAPSHOT, discover_config=True,
        options=sources.SourceOptions(completeness="complete"))
    assert stale_kinds(gated.check([path], as_of=FRESH)) == []
    assert stale_kinds(gated.check([path], as_of=STALE)) == ["baseline:stale"]


def test_omitting_as_of_still_evaluates_staleness(tmp_path, monkeypatch):
    """OMITTED MEANS RESOLVED, NOT DROPPED.

    The old reading — omitted means staleness is never evaluated — is a
    fail-open hole on exactly the path this input protects: the PostToolUse
    hook is invoked with one fixed command line and would otherwise treat a
    six-month-old auto-discovered state file as current forever.
    """
    monkeypatch.setenv(freshness.NOW_ENV, STALE)      # eight days past capture
    path = stale_repo(tmp_path)
    gated = PolicyGroundingGate(
        SNAPSHOT, discover_config=True,
        options=sources.SourceOptions(completeness="complete"))
    result = gated.check([path])                      # no flag, no argument
    assert stale_kinds(result) == ["baseline:stale"]
    assert "past its age ceiling" in "\n".join(result.findings())
    assert result.ok is True                          # staleness never blocks


def test_an_explicit_none_ceiling_suppresses_staleness(tmp_path, monkeypatch):
    """``max_age`` is the ceiling and ``off`` spells NO ceiling — the typed
    opt-out, which is the only way staleness is switched off."""
    assert freshness.parse_duration("off") is None
    monkeypatch.setenv(freshness.NOW_ENV, STALE)
    path = stale_repo(tmp_path, max_age="off")
    gated = PolicyGroundingGate(
        SNAPSHOT, discover_config=True,
        options=sources.SourceOptions(completeness="complete"))
    assert stale_kinds(gated.check([path])) == []


# -- resolving the sources at construction ------------------------------------


def disagreeing_estate(tmp_path: Path) -> Path:
    """A second view of the estate that disagrees about ONE security field of
    a resource no file in the changed set touches."""
    payload = json.loads(ESTATE.read_text(encoding="utf-8"))
    payload["firewall_rules"][FW_KEY]["source_ranges"] = ["0.0.0.0/0"]
    path = tmp_path / "other_snapshot.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_a_merged_disagreement_is_noted_once_across_a_three_file_set(tmp_path):
    """Source notes are ESTATE-WIDE. A copy attached to every file's report
    would multiply them by the changed-file count and inflate the counts."""
    empty = tmp_path / "empty.policy.json"
    empty.write_text(json.dumps({"etag": "BwX=", "version": 3}), encoding="utf-8")
    changed = [empty, POLICIES / "iam_policy_good.json",
               POLICIES / "org_policy_good.json"]

    plain = PolicyGroundingGate(SNAPSHOT).check(changed)
    assert [f.status for f in plain.files] == ["ok", "ok", "ok"]
    assert plain.risk == "none"

    gated = PolicyGroundingGate(
        ESTATE, resolve_sources=True,
        options=sources.SourceOptions(extra=(str(disagreeing_estate(tmp_path)),),
                                      completeness="complete", now=FRESH))
    assert gated.state_configured is True
    assert any(v.kind == drift.DRIFT_MATERIAL for v in gated.source_notes)
    result = gated.check(changed, as_of=FRESH)

    material = [v for f in result.files for v in f.verdicts
                if v.kind == drift.DRIFT_MATERIAL]
    assert len(material) == 1, "an estate-wide note was multiplied per file"
    assert result.files[0].verdicts[-1].kind == drift.DRIFT_MATERIAL
    assert [f.status for f in result.files] == ["unverified", "ok", "ok"]
    assert result.ok is True and result.risk == "low"
    # No synthetic entry: one result per changed file, still.
    assert len(result.files) == len(changed)

    # Two successive check calls each attach exactly once.
    again = gated.check(changed, as_of=FRESH)
    assert len([v for f in again.files for v in f.verdicts
                if v.kind == drift.DRIFT_MATERIAL]) == 1


def test_a_broken_primary_still_raises_from_the_constructor(tmp_path):
    """Construction stays STRICT: a broken snapshot is a setup error, not bad
    input, and ``resolve_sources`` does not turn it into a quiet empty view."""
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        PolicyGroundingGate(broken, resolve_sources=True)
    with pytest.raises(ValueError):
        PolicyGroundingGate(broken)


def test_a_secret_in_a_merged_source_never_reaches_a_report_message(tmp_path):
    """The loading boundary withholds a sensitive value and the gate scrubs the
    report against the process vault, so a note that quotes one is masked
    before any consumer can read it."""
    sources.vault().add(SECRET)
    note = Verdict("unverified", "state:source", "current-state", 0,
                   f"a source declared the value {SECRET} for a sensitive field")
    gated = PolicyGroundingGate(SNAPSHOT, current=drifting_state(note))
    result = gated.check(committed("org_policy_good.json"), as_of=FRESH)
    messages = "\n".join(v.message for f in result.files for v in f.verdicts)
    assert SECRET not in messages
    assert redact.WIRE_PREFIX in messages
    assert SECRET not in json.dumps(result.to_dict())


# -- the fail-open belt -------------------------------------------------------


def test_a_crashing_engine_yields_one_engine_crashed_and_the_gate_returns(
        monkeypatch):
    """``engine.evaluate``'s own contract is never-raise, and the gate's belt
    does not ride on it: a stage that raises becomes exactly one
    ``engine:crashed`` verdict and the gate still answers."""
    def boom(*args, **kwargs):
        raise RuntimeError("the baseline stage exploded")

    monkeypatch.setattr(baseline, "derive", boom)
    gated = PolicyGroundingGate(SNAPSHOT, current=estate_state())
    result = gated.check(committed("iam_policy_good.json"), as_of=FRESH)
    crashed = [v for f in result.files for v in f.verdicts
               if v.kind == engine.CRASHED_KIND]
    assert len(crashed) == 1 and crashed[0].status == "unverified"
    assert "the baseline stage exploded" in crashed[0].message
    assert result.ok is True and result.risk == "low"
    assert crashed[0].message in "\n".join(result.findings())


def test_an_unreadable_policy_file_still_fails_open_on_the_state_path(tmp_path):
    """The same fail-open discipline as ``ground_policy``: an unparseable
    document is feedback for the generator, never an exception."""
    broken = tmp_path / "broken.policy.json"
    broken.write_text("{not json", encoding="utf-8")
    gated = PolicyGroundingGate(SNAPSHOT, current=estate_state())
    result = gated.check([broken, tmp_path / "gone.policy.json"], as_of=FRESH)
    assert result.ok and result.risk == "low"
    assert [f.status for f in result.files] == ["unverified", "unverified"]
    text = "\n".join(result.findings())
    assert "not valid JSON" in text and "could not be read" in text
    assert len(result.files) == 2


# -- the third input ----------------------------------------------------------


def test_unavailable_requirements_fail_open_with_exactly_one_note(tmp_path):
    """The RULE SET is the third input and nobody else on the gate path builds
    one. A requirements document that will not load is one note — never a
    raise, and never silence."""
    path = policy_file(tmp_path, "same.policy.json", CURRENT_BINDINGS)
    missing = tmp_path / "nowhere.promises.json"
    settings = iam_settings(path, requirements=str(missing))
    gated = PolicyGroundingGate(SNAPSHOT, current=estate_state(),
                                settings=settings)
    result = gated.check([path], as_of=FRESH)
    carried = [v for v in result.files[0].verdicts
               if v.kind in ("sec:artifact", engine.RULES_KIND)]
    assert len(carried) == 1
    assert str(missing) in carried[0].message
    assert result.ok is True
