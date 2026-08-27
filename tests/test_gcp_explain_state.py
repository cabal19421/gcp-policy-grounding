"""Acceptance for :mod:`gcp_grounding.explain_state` — the audit surface.

Everything here is IN-PROCESS and constructs its three inputs directly: the
module is PURE RENDERING over an ``engine.EvaluationResult``, a
``provenance.SourceLedger`` and a ``discovery.Settings``, so driving the whole
engine to produce them would test the engine and not this renderer.

The load-bearing tests, and the failure each one guards:

- :func:`test_the_new_resource_line_and_the_unqueried_line_read_differently` —
  ``baseline:new`` means a source that enumerates this domain COMPLETELY was
  queried and there is no predecessor; ``baseline:unqueried`` means we never
  looked. They license opposite conclusions, and a render that shows them alike
  is the collapse the design calls the most dangerous thing it could do.
- :func:`test_a_boundary_is_rendered_and_a_source_without_one_shows_no_within` —
  complete-within-one-boundary and complete are different claims. Printing them
  identically is how a reader is misled into trusting an estate-wide negative.
- :func:`test_no_configured_source_renders_exactly_the_one_line_form` — silence
  reads as a clean estate check, which is the strongest claim this tool can
  make and the one it has least earned.
- :func:`test_a_redacted_record_renders_the_wire_form_and_never_the_original`
  and :func:`test_the_belt_refuses_a_render_carrying_a_vault_plaintext` — the
  two halves of the redaction belt. ``Redacted.__repr__`` prints the digest
  BARE, so rendering through ``repr`` alone would be a regression this asserts
  against by counting prefixes rather than by looking for the digest.

No capability branch is needed: this module touches neither the solver nor the
filesystem.
"""

from __future__ import annotations

import json
import logging

import pytest

from gcp_grounding import (
    baseline,
    compare,
    discovery,
    engine,
    explain_state,
    freshness,
    provenance,
    redact,
    sources,
)
from gcp_grounding.baseline import BaselineEntry, Candidate, Derivation, TargetRef
from gcp_grounding.core import log as core_log
from gcp_grounding.core.report import GroundingReport
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.provenance import LedgerBuilder

CAPTURED_AT = "2026-07-18T09:30:00Z"
OLDER_AT = "2026-07-11T09:30:00Z"
NOW = "2026-07-20T09:30:00Z"

IAM_KEY = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
FW_KEY = "projects/acme-prod/global/firewalls/allow-ssh"
NEW_FW_KEY = "projects/acme-prod/global/firewalls/allow-metrics"
ORG_KEY = "organizations/1/policies/iam.disableServiceAccountKeyCreation"

BOUNDARY = "organizations/1"
ADDRESS = "google_compute_firewall.ssh"

SECRET = "EXPLAIN-STATE-CANARY-a4f2c81b-not-a-real-secret"


# -- isolation ----------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_boundary(monkeypatch):
    """A FRESH process vault and log filter per test, restored exactly.

    The renderers install the secret boundary as a side effect (that is the
    point of ``ensure_log_filter`` at a render boundary), and neither the vault
    nor the handler set may leak into the rest of the suite: a canary left in
    the process vault would scrub a later module's output.
    """
    root = logging.getLogger(redact._HARNESS_ROOT)
    saved_handlers = list(root.handlers)
    saved_filters = {handler: list(handler.filters) for handler in saved_handlers}
    monkeypatch.setattr(sources, "_VAULT", None)
    monkeypatch.setattr(redact, "_INSTALLED", None)
    monkeypatch.setattr(redact, "_OWNED_HANDLER", None)
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


# -- the fixture estate -------------------------------------------------------


def fw_record(**overrides) -> dict:
    record = {
        "network": "projects/acme-prod/global/networks/vpc-main",
        "direction": "INGRESS",
        "action": "allow",
        "priority": 1000,
        "disabled": False,
        "source_ranges": ["10.0.0.0/8"],
        "destination_ranges": [],
        "source_tags": [],
        "target_tags": [],
        "source_service_accounts": [],
        "target_service_accounts": [],
        "layer4": [{"protocol": "tcp", "ports": ["22"]}],
    }
    record.update(overrides)
    return record


API_FW = fw_record()
TF_FW = fw_record(source_ranges=["0.0.0.0/0"])
IAM_RECORD = {"bindings": [{"role": "roles/bigquery.dataViewer",
                            "members": ["user:alice@acme.example"]}]}


def two_source_ledger(*, iam_boundary: str = BOUNDARY) -> provenance.SourceLedger:
    """An API capture complete within one organization, plus a partial tfstate.

    The two domains are deliberately asymmetric: ``iam_bindings`` keeps the
    API's boundary, while ``firewall_rules`` — which both sources speak for —
    is coerced to ``partial`` by the terraform contributor, which is exactly
    the pair the boundary assertions need.
    """
    builder = LedgerBuilder()
    builder.source("api-capture", "api", origin="<fetch:acme-prod>",
                   captured_at=CAPTURED_AT, scope="complete", boundary=iam_boundary)
    builder.source("tf-state", "tfstate", origin="/repo/terraform.tfstate",
                   captured_at=OLDER_AT, scope="partial", serial=7,
                   lineage="8f0c-lineage")
    builder.declare("iam_bindings", scope="complete", boundary=iam_boundary,
                    source_kinds=("api",))
    builder.declare("firewall_rules", scope="complete", source_kinds=("api",))
    builder.declare("firewall_rules", scope="partial", source_kinds=("tfstate",))
    builder.fact("iam_bindings", IAM_KEY, source_id="api-capture",
                 locator="//cloudresourcemanager.googleapis.com/projects/acme-prod")
    builder.fact("firewall_rules", FW_KEY, source_id="api-capture", locator=ADDRESS)
    builder.alternate("firewall_rules", FW_KEY, source_id="tf-state",
                      locator=ADDRESS, record=TF_FW,
                      reason="lower fidelity than the api capture")
    return builder.build()


def entries(*, iam_record=None) -> tuple[BaselineEntry, ...]:
    """One entry of each shape the blocks have to tell apart."""
    return (
        BaselineEntry(
            target=TargetRef(category="iam_bindings", key=IAM_KEY, how="tool-input"),
            status="resolved", key=IAM_KEY, document=IAM_RECORD, kind="iam_policy",
            record=IAM_RECORD if iam_record is None else iam_record,
            source_id="api-capture", scope="complete"),
        BaselineEntry(
            target=TargetRef(category="firewall_rules", key=NEW_FW_KEY,
                             how="document-name"),
            status="absent", key=NEW_FW_KEY, scope="complete",
            reason="the api capture enumerates 'firewall_rules' completely and holds "
                   "no row for this key"),
        BaselineEntry(
            target=TargetRef(category="org_policies", key=ORG_KEY, how="config-map"),
            status="unqueried", key=ORG_KEY, scope="uncaptured",
            reason="no source covering 'org_policies' was configured, so the domain "
                   "was never enumerated"),
        BaselineEntry(
            target=TargetRef(category="firewall_rules", key=FW_KEY, how="tf-address",
                             address=ADDRESS),
            status="conflict", key=FW_KEY, document=API_FW, kind="firewall_rule",
            record=API_FW, source_id="api-capture", scope="complete",
            others=(Candidate(source_id="tf-state", kind="tfstate", record=TF_FW,
                              locator=ADDRESS, reason="lower fidelity"),),
            flags=("conflict",),
            reason="two sources describe this row and they disagree"),
    )


def result(*, derivation_entries=None, current=None) -> engine.EvaluationResult:
    proposal = engine.prepare_proposal({"bindings": []}, "iam_policy",
                                       source="<proposal>")
    derivation = None
    if derivation_entries is not None:
        derivation = Derivation(entries=derivation_entries)
    return engine.EvaluationResult(report=GroundingReport(), proposal=proposal,
                                   current=current, derivation=derivation)


def settings(**cli) -> discovery.Settings:
    """Settings whose ``primary`` came from a named config file and whose clock
    came from a flag, so both origin labels are exercised."""
    config = discovery.Config(path="/repo/.gcp-grounding.json", directory="/repo",
                              values={"primary": "/repo/snapshot.json"})
    flags = {"now": NOW}
    flags.update(cli)
    return discovery.resolve_settings(cli=flags, env={}, config=config)


def lines(**kwargs) -> list[str]:
    return explain_state.state_lines(
        result(derivation_entries=entries()), two_source_ledger(), **kwargs)


def find(rendered, needle: str) -> str:
    matches = [line for line in rendered if needle in line]
    assert len(matches) == 1, f"expected exactly one line containing {needle!r}, " \
                              f"got {matches}"
    return matches[0]


# -- BLOCK COVERAGE -----------------------------------------------------------


def test_all_four_blocks_render_for_a_two_source_run():
    rendered = lines(settings=settings())

    assert rendered[0].startswith(f"{explain_state.HEADER}:"), \
        "the first line must always say state was used, so the block is greppable"
    assert "2 source(s)" in rendered[0] and "4 target(s)" in rendered[0]
    assert "1 conflicting" in rendered[0]
    for block in ("sources:", "settings:", "targets:", "drift:"):
        assert block in rendered, f"block {block!r} is missing from the render"
    # BLOCK ONE embeds the coverage table rather than re-deriving it.
    assert "  coverage:" in rendered
    assert any(line.strip() == f"source coverage ({provenance.SCHEMA})"
               for line in rendered)
    # BLOCK FOUR names the differing path and both sources' values.
    drift_line = find(rendered, "source_ranges:")
    assert "api-capture=" in drift_line and "tf-state=" in drift_line
    assert "0.0.0.0/0" in drift_line and "10.0.0.0/8" in drift_line


def test_the_new_resource_line_and_the_unqueried_line_read_differently():
    """THE collapse this design calls the most dangerous one it could make.

    'we looked with a source that enumerates this domain and there is no
    predecessor' and 'we never looked' license opposite conclusions.
    """
    rendered = lines()
    new_line = find(rendered, NEW_FW_KEY)
    unqueried_line = find(rendered, ORG_KEY)

    assert new_line != unqueried_line
    assert new_line.split("->")[1] != unqueried_line.split("->")[1], \
        "the two statuses must not render the same text after the arrow"
    assert "NEW RESOURCE" in new_line and "NEW RESOURCE" not in unqueried_line
    assert "NOT LOOKED UP" in unqueried_line and "NOT LOOKED UP" not in new_line
    # And neither swallows the other, so grepping for one cannot match both.
    tail_new = new_line.split("->", 1)[1]
    tail_unqueried = unqueried_line.split("->", 1)[1]
    assert tail_new not in tail_unqueried and tail_unqueried not in tail_new


def test_a_reason_that_names_something_prints_and_a_restatement_does_not():
    """The reason line earns its place by ADDING DATA, and this fixture holds
    one of each: the absent and unqueried entries name the source that
    enumerated the domain and the category nobody covered, while the conflict
    entry's reason ("two sources describe this row and they disagree") is the
    status phrase one line above it in other words. The restatement is dropped
    from the HUMAN render only — ``state_document`` carries every reason
    verbatim, which is asserted right below."""
    rendered = lines()
    reasons = [line for line in rendered if line.startswith("    reason: ")]

    assert len(reasons) == 2, "the conflict entry's reason restates its phrase"
    assert any("enumerates 'firewall_rules' completely" in line for line in reasons)
    assert any("no source covering 'org_policies'" in line for line in reasons)
    conflict_line = find(rendered, FW_KEY + " ->")
    assert "conflict - two or more sources describe this row" in conflict_line
    assert not any("they disagree" in line for line in rendered)
    resolved_line = find(rendered, IAM_KEY + " ->")
    assert "resolved" in resolved_line


def test_a_suppressed_reason_is_still_in_the_machine_document():
    """Nothing is DROPPED, only un-printed: the reason the human render leaves
    off the conflict entry is the reason ``--state-explain --format json``
    hands a consumer."""
    document = explain_state.state_document(
        result(derivation_entries=entries()), two_source_ledger())
    [conflict] = [row for row in document["targets"] if row["key"] == FW_KEY]
    assert conflict["reason"] == "two sources describe this row and they disagree"


def test_status_phrases_are_total_over_the_resolution_statuses():
    """A status with no phrase would render as a bare word next to six
    sentences, which is how the two dangerous ones start to look alike."""
    assert set(explain_state.STATUS_PHRASES) == set(baseline.RESOLUTION_STATUSES)


def test_the_targets_block_says_so_when_no_target_was_derived():
    rendered = explain_state.state_lines(result(), two_source_ledger())
    target_line = find(rendered, "targets:")

    assert "none" in target_line and "no baseline target was derived" in target_line
    assert find(rendered, "drift:").startswith("drift: none")


# -- BLOCK ONE: the boundary --------------------------------------------------


def test_a_boundary_is_rendered_and_a_source_without_one_shows_no_within():
    rendered = lines()
    api_line = find(rendered, "[api] api-capture")
    tf_line = find(rendered, "[tfstate] tf-state")

    assert f"scope=complete within '{BOUNDARY}'" in api_line
    assert f"iam_bindings=complete within '{BOUNDARY}'" in api_line
    assert "within" not in tf_line, \
        "a source that declared no boundary must not render one"
    assert "scope=partial" in tf_line
    assert "facts=2" in api_line and "facts=0" in tf_line


def test_a_terraform_source_explains_its_partial_scope_beneath_the_line():
    rendered = lines()
    index = rendered.index(find(rendered, "[tfstate] tf-state"))
    notes = []
    for line in rendered[index + 1:]:
        if not line.startswith("    note: "):
            break
        notes.append(line)

    assert any("capped at 'partial' by construction" in note for note in notes), \
        "partial must not read as a capture bug"
    assert any("serial=7" in note for note in notes)


def test_the_age_is_rendered_against_the_injected_clock_and_never_the_wall_clock():
    with_clock = lines(settings=settings())
    assert "age=2 days" in find(with_clock, "[api] api-capture")
    assert "age=9 days" in find(with_clock, "[tfstate] tf-state")

    without_clock = lines()
    assert "age=unknown (no clock was injected)" in \
        find(without_clock, "[api] api-capture")


def test_an_unparseable_capture_time_renders_an_unknown_age():
    builder = LedgerBuilder()
    builder.source("naive", "api", origin="<fetch>", captured_at="2026-07-18 09:30",
                   scope="complete")
    builder.declare("iam_bindings", scope="complete", source_kinds=("api",))
    rendered = explain_state.state_lines(result(), builder.build(),
                                         settings=settings())

    assert "age=unknown (no aware capture timestamp)" in find(rendered, "[api] naive")


# -- BLOCK TWO: the settings --------------------------------------------------


def test_the_settings_origin_labels_appear_verbatim():
    """The fields somebody CHOSE get their own row, in an aligned key column,
    with the origin label verbatim; the ones still on their built-in default
    are named together on one totality line.

    TOTALITY IS THE POINT AND IT IS UNCHANGED: an input nobody can see is an
    input nobody can audit, so every name in ``SETTINGS_FIELDS`` is still
    visible on every render — as a row when it was set, on the defaults line
    when it was not, and never in neither place.
    """
    rendered = lines(settings=settings(max_age="3d"))

    assert "  primary = /repo/snapshot.json [config /repo/.gcp-grounding.json]" \
        in rendered
    assert f"  now     = {NOW} [cli]" in rendered
    assert "  max_age = 3d [cli]" in rendered
    [totality] = [line for line in rendered if "settings at defaults:" in line]
    assert totality.startswith("  12 settings at defaults: ")
    defaulted = totality.split(": ", 1)[1].split(", ")
    assert "precedence" in defaulted
    assert len(defaulted) == 12
    # TOTAL over the settings fields: every name visible, every run.
    for name in discovery.SETTINGS_FIELDS:
        row = any(line.startswith(f"  {name} ") and " = " in line
                  for line in rendered)
        assert row or name in defaulted, name
        assert not (row and name in defaulted), name


def test_the_settings_value_column_is_the_option_and_the_label_is_the_origin():
    """``Settings.origins`` is the per-field ORIGIN LABEL map while
    ``settings.options.origins`` is the snapshot's SIDECAR PATH — one spelling,
    two meanings, and reading one as the other prints a path where a label
    belongs."""
    config = discovery.Config(path="/repo/.gcp-grounding.json", directory="/repo",
                              values={"primary": "/repo/snapshot.json"})
    resolved = discovery.resolve_settings(
        cli={"origins": "/repo/snapshot.origins.json"}, env={}, config=config)
    rendered = explain_state.state_lines(result(), two_source_ledger(),
                                         settings=resolved)

    assert "  origins = /repo/snapshot.origins.json [cli]" in rendered


def test_no_settings_means_no_settings_block():
    rendered = lines()
    assert "settings:" not in rendered
    assert "sources:" in rendered and "targets:" in rendered


# -- THE NOTHING-CONFIGURED FORM ----------------------------------------------


def test_no_configured_source_renders_exactly_the_one_line_form():
    empty = provenance.SourceLedger()

    assert explain_state.state_lines(result(derivation_entries=entries()),
                                     empty) == [explain_state.NONE_CONFIGURED]
    assert explain_state.state_lines(result(), None) == \
        [explain_state.NONE_CONFIGURED]
    assert "only proposal-tier checks ran" in explain_state.NONE_CONFIGURED
    assert explain_state.NONE_CONFIGURED.startswith(f"{explain_state.HEADER}:")


# -- THE MACHINE DOCUMENT -----------------------------------------------------


def document(**kwargs) -> dict:
    return explain_state.state_document(
        result(derivation_entries=entries()), two_source_ledger(), **kwargs)


def test_the_document_round_trips_through_json_and_is_byte_stable():
    first = document(settings=settings())
    second = document(settings=settings())

    assert json.loads(json.dumps(first)) == first, \
        "only JSON-native types may reach the document"
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert set(first) == {"schema", "as_of", "sources", "settings", "targets", "drift"}
    assert first["schema"] == explain_state.PROVENANCE_SCHEMA
    assert first["as_of"] == freshness.parse_timestamp(NOW).isoformat()


def test_the_document_lists_are_deterministically_ordered():
    doc = document(settings=settings())

    assert [row["source"] for row in doc["sources"]] == ["tf-state", "api-capture"], \
        "sources are ordered by FIDELITY then source id, weakest first"
    assert [(row["domain"], row["key"]) for row in doc["targets"]] == \
        sorted((row["domain"], row["key"]) for row in doc["targets"])
    assert [row["path"] for row in doc["drift"]] == \
        sorted(row["path"] for row in doc["drift"])
    assert doc["drift"] and doc["drift"][0]["path"] == "source_ranges"
    assert sorted(entry["source"] for entry in doc["drift"][0]["values"]) == \
        ["api-capture", "tf-state"]


def test_the_document_carries_the_boundary_per_domain():
    doc = document()
    api = [row for row in doc["sources"] if row["source"] == "api-capture"][0]
    domains = {row["domain"]: row for row in api["domains"]}

    assert api["boundary"] == BOUNDARY
    assert domains["iam_bindings"]["boundary"] == BOUNDARY
    assert domains["iam_bindings"]["scope"] == "complete"
    assert domains["firewall_rules"]["scope"] == "partial", \
        "a terraform contributor caps the joined scope at partial"
    assert domains["firewall_rules"]["boundary"] == ""


def test_the_document_without_settings_carries_an_empty_settings_list():
    doc = document()

    assert doc["settings"] == []
    assert doc["as_of"] == OLDER_AT, \
        "with no injected clock the document dates itself by the OLDEST capture"


def test_the_document_names_the_statuses_the_lines_distinguish():
    doc = document()
    statuses = {row["key"]: row["status"] for row in doc["targets"]}

    assert statuses[NEW_FW_KEY] == "absent"
    assert statuses[ORG_KEY] == "unqueried"
    assert statuses[FW_KEY] == "conflict"
    conflict = [row for row in doc["targets"] if row["key"] == FW_KEY][0]
    assert conflict["alternates"] == ["tf-state"]


# -- THE DRILL-DOWN -----------------------------------------------------------


def test_fact_lines_shows_the_winner_the_alternate_and_the_differing_path():
    rendered = explain_state.fact_lines(
        result(derivation_entries=entries()), two_source_ledger(),
        "firewall_rules", FW_KEY)

    chosen = find(rendered, "  chosen:")
    assert "source=api-capture" in chosen and "[api]" in chosen
    assert f"locator={ADDRESS}" in chosen
    assert "domain-scope=partial" in chosen
    assert any("10.0.0.0/8" in line for line in rendered), "the winner's record"
    alternate = find(rendered, "    alternate:")
    assert "source=tf-state" in alternate and "lower fidelity" in alternate
    assert any("0.0.0.0/0" in line for line in rendered), "the alternate's record"
    diff = find(rendered, "    source_ranges:")
    assert "api-capture=" in diff and "tf-state=" in diff


def test_fact_lines_answers_for_a_key_no_baseline_entry_covered():
    snapshot = GcpSnapshot(captured_at=CAPTURED_AT,
                           firewall_rules={FW_KEY: API_FW})
    rendered = explain_state.fact_lines(result(current=snapshot),
                                        two_source_ledger(), "firewall_rules", FW_KEY)

    assert "source=api-capture" in find(rendered, "  chosen:")
    assert any("10.0.0.0/8" in line for line in rendered)
    assert find(rendered, "    none - no comparable field difference")


def test_fact_lines_says_so_when_nothing_describes_the_row():
    rendered = explain_state.fact_lines(result(), two_source_ledger(),
                                        "firewall_rules", "projects/x/nope")

    assert "  chosen: source=- [-]" in find(rendered, "  chosen:")
    assert "record: none" in find(rendered, "    record: none")
    assert "  alternates: 0" in rendered


# -- THE REDACTION BELT -------------------------------------------------------


def test_a_redacted_record_renders_the_wire_form_and_never_the_original():
    """``Redacted.__repr__`` prints the digest BARE, so a renderer that reached
    for ``repr`` alone would pass a naive 'the secret is absent' assertion and
    still print an unqualified hash. The prefix count is what pins it."""
    withheld = redact.Redacted.of(SECRET, "values.private_key")
    record = {"bindings": [{"role": "roles/owner", "members": ["user:a@b.example"]}],
              "etag": withheld}
    rendered = explain_state.fact_lines(
        result(derivation_entries=entries(iam_record=record)), two_source_ledger(),
        "iam_bindings", IAM_KEY)
    text = "\n".join(rendered)

    assert SECRET not in text
    assert withheld.wire() in text
    assert text.count(withheld.digest) == text.count(withheld.wire()), \
        "the digest must never be printed bare, only inside its wire form"


def test_the_belt_refuses_a_render_carrying_a_vault_plaintext():
    """In production the value was replaced at load time; this is the belt that
    turns a regression into an AssertionError instead of a leak."""
    sources.vault().add(SECRET)
    leaking = (BaselineEntry(
        target=TargetRef(category="firewall_rules", key=FW_KEY, how="tf-address"),
        status="unqueried", key=FW_KEY,
        reason=f"the reader kept the plaintext {SECRET} in its note"),)

    with pytest.raises(AssertionError, match="refusing to ship a leak"):
        explain_state.state_lines(result(derivation_entries=leaking),
                                  two_source_ledger())
    with pytest.raises(AssertionError, match="refusing to ship a leak"):
        explain_state.state_document(result(derivation_entries=leaking),
                                     two_source_ledger())


def test_the_belt_names_no_value_when_it_fires():
    sources.vault().add(SECRET)
    leaking = (BaselineEntry(
        target=TargetRef(category="firewall_rules", key=FW_KEY, how="tf-address"),
        status="unqueried", key=FW_KEY, reason=SECRET),)

    with pytest.raises(AssertionError) as caught:
        explain_state.state_lines(result(derivation_entries=leaking),
                                  two_source_ledger())

    assert SECRET not in str(caught.value), \
        "an assertion that prints the secret to prove it leaked IS the leak"
    assert "length" in str(caught.value) and "process vault" in str(caught.value), \
        "it must still say enough to find the offending line"


def test_a_clean_render_leaves_the_vault_untouched_and_costs_nothing():
    sources.vault().add(SECRET)
    rendered = lines(settings=settings())

    assert all(SECRET not in line for line in rendered)


def test_both_renderers_reattach_the_log_filter_after_setup_logging():
    """``setup_logging`` REMOVES and re-adds its own handlers, so the install in
    ``sources.py`` is gone the moment anything reconfigures logging — and this
    surface is exactly where a withheld value would then be logged.

    THE HARNESS LOGGER IS RESTORED AFTERWARDS. This test deliberately
    reconfigures a PROCESS-WIDE logger; leaving it reconfigured leaked into every
    later module in the session — ``test_gcp_preflight``'s traceback assertion
    saw its one record twice, and only in a full run — so the handler list and
    the propagate flag are put back in a ``finally``. The assertions are
    unchanged; only the blast radius is.
    """
    root = logging.getLogger(redact._HARNESS_ROOT)
    saved_handlers = list(root.handlers)
    saved_propagate = root.propagate
    saved_level = root.level
    try:
        root.handlers[:] = []
        sources.vault()                       # the single install
        core_log.setup_logging()              # ... whose own handlers carry no filter
        reconfigured = [handler for handler in root.handlers
                        if getattr(handler, "_harness_owned", False)]
        assert reconfigured, "setup_logging added no handler of its own"
        assert not any(isinstance(f, redact.SecretScrubFilter)
                       for handler in reconfigured for f in handler.filters)

        lines(settings=settings())

        assert all(redact._INSTALLED in handler.filters for handler in root.handlers)
        filt = redact._INSTALLED
        document(settings=settings())
        assert redact._INSTALLED is filt
        assert all(filt in handler.filters for handler in root.handlers)
    finally:
        root.handlers[:] = saved_handlers
        root.propagate = saved_propagate
        root.setLevel(saved_level)


# -- THE ONE DIFF RULE --------------------------------------------------------


def test_the_drift_block_reports_an_incomparable_pair_rather_than_dropping_it():
    """Two views that cannot be compared AT ALL is the most important thing on
    the block, not the least."""
    bad = BaselineEntry(
        target=TargetRef(category="iam_bindings", key=IAM_KEY, how="tool-input"),
        status="conflict", key=IAM_KEY, record=IAM_RECORD, source_id="api-capture",
        others=(Candidate(source_id="tf-state", kind="tfstate",
                          record={"bindings": [{"role": "roles/owner",
                                                "unknown_key": True}]}),),
        reason="the two readings disagree")
    with pytest.raises(compare.Incomparable):
        compare.compare("iam_bindings", bad.record, bad.others[0].record)

    rendered = explain_state.state_lines(result(derivation_entries=(bad,)),
                                         two_source_ledger())

    assert "incomparable" in find(rendered, "    <record>:")
