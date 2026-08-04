"""Acceptance for `gcp_grounding.drift`: the one drift vocabulary and the
taint adjudicator.

Three things are pinned here that are easy to get subtly wrong.

ONE, VOLATILE IS NOT BENIGN. A volatile field yields no `compare.FieldDiff` at
all, so it never becomes a dispute and never becomes a verdict. That is driven
through `compare.compare` rather than asserted against a hand-written dispute
list, so the two modules are pinned together and a field moved from the
volatile list to a benign one fails here.

TWO, THE CAP IS FAIR. The budget is filled round-robin over the drift kinds, so
the single verdict of a rare kind survives a flood of one common kind. The
assertion is BY KIND, so a naive head-truncation of a sorted list fails it.

THREE, THE CARVE-OUT'S BOUNDARY. A `contradicted` whose whole read set is a
phantom is downgraded; the SAME verdict with one more undisputed fact in its
read set is not. They are asserted side by side, because the carve-out is only
sound because of that boundary.
"""

from __future__ import annotations

import pytest

from gcp_grounding import compare, drift, merge, reconciled
from gcp_grounding.core.report import GroundingReport, Verdict
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.provenance import (
    CategoryScope,
    Dispute,
    FactOrigin,
    SourceLedger,
    SourceRecord,
)
from gcp_grounding.reconciled import ReconciledSnapshot

CAPTURED = "2026-01-01T00:00:00Z"
RULE = "projects/acme-prod/global/firewalls/allow-internal"
OTHER = "projects/acme-prod/global/firewalls/deny-ssh-external"

API = SourceRecord(source_id="api-capture", kind="api", scope="complete",
                   origin="compute.firewalls.list")
TFSTATE = SourceRecord(source_id="tf-state", kind="tfstate", scope="partial",
                       origin="terraform.tfstate")

#: Only fields `compare.FIELDS['firewall_rules']` classifies, so an
#: unclassified key cannot manufacture an `unmergeable` diff and hide the point.
BASE_RULE = {
    "network": "projects/acme-prod/global/networks/vpc",
    "direction": "INGRESS",
    "action": "allow",
    "priority": 1000,
    "disabled": False,
    "source_ranges": ["10.0.0.0/8"],
    "layer4": [{"protocol": "tcp", "ports": ["22"]}],
    "description": "internal ssh",
}

#: Every member of `compare.VOLATILE_IGNORED`, with a DIFFERENT value on each
#: side. Two views of one unchanged resource disagree on all of them.
VOLATILE_LEFT = {
    "etag": "AAA=", "self_link": "https://left/one", "selfLink": "https://left/two",
    "id": "111", "fingerprint": "left-print", "creation_timestamp": "2020-01-01",
    "creationTimestamp": "2020-01-01", "labels": {"owner": "left"},
    "terraform_address": "google_compute_firewall.left", "project_number": "1",
}
VOLATILE_RIGHT = {
    "etag": "BBB=", "self_link": "https://right/one", "selfLink": "https://right/two",
    "id": "222", "fingerprint": "right-print", "creation_timestamp": "2024-06-06",
    "creationTimestamp": "2024-06-06", "labels": {"owner": "right"},
    "terraform_address": "google_compute_firewall.right", "project_number": "2",
}


# -- builders -----------------------------------------------------------------


def _ledger(*, sources=(), categories=None, facts=None, disputes=()) -> SourceLedger:
    return SourceLedger(
        sources={record.source_id: record for record in sources},
        categories=dict(categories or {}),
        facts=dict(facts or {}),
        disputes=tuple(disputes))


def _snapshot(ledger: SourceLedger | None = None, *, disputes=(),
              **fields) -> ReconciledSnapshot:
    return ReconciledSnapshot.from_snapshot(
        GcpSnapshot(captured_at=CAPTURED, **fields),
        ledger=ledger, disputes=tuple(disputes), policy_name="highest-fidelity-wins")


def _field_disputes(category: str, key: str, left, right, *,
                    winner="api-capture", loser="tf-state") -> tuple[Dispute, ...]:
    """The disputes `merge._compare_pair` would mint for this pair.

    Built THROUGH `compare.compare` rather than by hand: this is the seam the
    volatile/benign distinction lives on, and a hand-written dispute list would
    happily assert a difference `compare` never reports.
    """
    out = []
    for diff in compare.compare(category, left, right):
        if diff.left is None or diff.right is None:
            continue                     # absence is merge step 8's question
        out.append(Dispute(
            category=category, key=key, field=diff.path, severity=diff.severity,
            left=repr(diff.left), right=repr(diff.right),
            reason=f"'{winner}' and '{loser}' disagree about '{diff.path}' in "
                   f"{category}/{key}"))
    return tuple(out)


def _existence_dispute(category: str = "firewall_rules", key: str = RULE) -> Dispute:
    return Dispute(
        category=category, key=key, field="", severity="material",
        left="tf-state", right="api-capture",
        reason=f"'{key}' is present in ['tf-state'] but ABSENT from "
               f"'api-capture', which enumerated '{category}' completely; it may "
               f"have been destroyed or moved out of band")


def _kinds(verdicts) -> list[str]:
    return [v.kind for v in verdicts]


# -- the vocabulary -----------------------------------------------------------


def test_the_vocabulary_is_exactly_six_kinds_and_merge_shares_it():
    assert drift.DRIFT_KINDS == ("drift", "drift:material", "drift:unmanaged",
                                 "drift:unmergeable", "drift:verdict",
                                 "drift:key-mismatch")
    # ONE vocabulary: merge's step-9a kind is not a second spelling of it.
    assert drift.DRIFT_KEY_MISMATCH == merge.KEY_MISMATCH_KIND
    assert drift.DEFAULT_DRIFT_POLICY in drift.DRIFT_POLICIES
    # The round-robin fill can only keep its never-drop-the-first promise while
    # the budget is at least one slot per kind.
    assert drift.MAX_DRIFT_VERDICTS >= len(drift.DRIFT_KINDS)


# -- each dispute shape -------------------------------------------------------


def test_a_benign_field_difference_becomes_drift_naming_both_values():
    left = dict(BASE_RULE)
    right = dict(BASE_RULE, description="internal ssh (managed by terraform)")
    disputes = _field_disputes("firewall_rules", RULE, left, right)
    assert [d.severity for d in disputes] == ["benign"]

    out = drift.drift_verdicts(_ledger(disputes=disputes))
    assert _kinds(out) == ["drift"]
    message = out[0].message
    assert out[0].status == "unverified"
    assert "description" in message
    assert "internal ssh" in message and "managed by terraform" in message
    assert "not a security field" in message
    assert "NO CHECK WAS AFFECTED" in message


def test_a_material_field_conflict_names_the_winner_and_the_precedence():
    left = dict(BASE_RULE, priority=1000)
    right = dict(BASE_RULE, priority=900)
    disputes = _field_disputes("firewall_rules", RULE, left, right)
    assert [d.severity for d in disputes] == ["material"]

    ledger = _ledger(
        sources=(API, TFSTATE),
        categories={"firewall_rules": CategoryScope(scope="complete",
                                                    source_kinds=("api",))},
        facts={"firewall_rules": {RULE: FactOrigin(source_id="api-capture",
                                                   locator="compute.firewalls.list",
                                                   taint="disputed")}},
        disputes=disputes)
    out = drift.drift_verdicts(ledger, precedence="terraform-wins")
    assert _kinds(out) == ["drift:material"]
    message = out[0].message
    assert "priority" in message
    assert "1000" in message and "900" in message
    assert "api-capture" in message                     # which source won
    assert "terraform-wins" in message                  # under which precedence
    assert "ABSTAINS" in message


def test_a_material_existence_dispute_names_the_locator_and_keeps_the_fact():
    ledger = _ledger(
        sources=(API, TFSTATE),
        facts={"firewall_rules": {
            RULE: FactOrigin(source_id="tf-state",
                             locator="google_compute_firewall.allow_internal",
                             taint="disputed")}},
        disputes=(_existence_dispute(),))
    out = drift.drift_verdicts(ledger)
    assert _kinds(out) == ["drift:material"]
    message = out[0].message
    assert "google_compute_firewall.allow_internal" in message      # the locator
    assert "DESTROYED OR MOVED OUT OF BAND" in message
    assert "KEPT" in message


def test_an_unmergeable_dispute_carries_its_reason():
    reason = ("firewall_rules/legacy could not be canonicalised [ambiguous-project]: "
              "two projects claim number 4242; it is kept under its RAW key")
    dispute = Dispute(category="firewall_rules", key="legacy", field="",
                      severity="unmergeable", left="tf-state", right="",
                      reason=reason)
    out = drift.drift_verdicts(_ledger(disputes=(dispute,)))
    assert _kinds(out) == ["drift:unmergeable"]
    assert reason in out[0].message


def test_twenty_unmanaged_disputes_in_one_category_yield_exactly_one_verdict():
    disputes = tuple(
        Dispute(category="firewall_rules", key=f"projects/p/global/firewalls/r{i:02d}",
                field="", severity="unmanaged", left="api-capture", right="tf-state",
                reason="it exists but terraform does not manage it")
        for i in range(20))
    out = drift.drift_verdicts(_ledger(disputes=disputes))
    assert _kinds(out) == ["drift:unmanaged"]
    assert out[0].status == "unverified"
    assert out[0].target == "firewall_rules"
    assert "20 resource(s)" in out[0].message
    assert "NOT A FINDING" in out[0].message
    # Never one per resource: the individual names go to the debug log.
    assert "r00" not in out[0].message


# -- volatile is not benign ---------------------------------------------------


def test_a_volatile_only_difference_produces_no_dispute_and_zero_verdicts():
    left = dict(BASE_RULE, **VOLATILE_LEFT)
    right = dict(BASE_RULE, **VOLATILE_RIGHT)
    # compare.py is where this is decided: a volatile field yields NO FieldDiff.
    assert compare.compare("firewall_rules", left, right) == ()
    assert set(VOLATILE_LEFT) == set(compare.VOLATILE_IGNORED)

    disputes = _field_disputes("firewall_rules", RULE, left, right)
    assert disputes == ()
    assert drift.drift_verdicts(_ledger(disputes=disputes)) == ()


# -- terraform's own detected drift -------------------------------------------


PLAN_DRIFT_NOTE = (
    "resource_drift: terraform detected drift on 2 resource(s) "
    "(google_compute_firewall.allow_internal, google_compute_firewall.deny_ssh). "
    "The addresses are recorded and NO objects were taken from 'resource_drift': "
    "'prior_state' already reflects that refresh, so a second object set would "
    "double-count every one of them."
)


def test_a_ledger_resource_drift_note_yields_one_aggregate_drift_verdict():
    plan = SourceRecord(source_id="tf-plan", kind="tfplan-prior", scope="partial",
                        origin="plan.json", note=PLAN_DRIFT_NOTE)
    out = drift.drift_verdicts(_ledger(sources=(plan,)))
    assert _kinds(out) == ["drift"]
    assert out[0].target == "resource_drift"
    assert "2 resource(s)" in out[0].message
    assert "google_compute_firewall.allow_internal" in out[0].message
    assert "google_compute_firewall.deny_ssh" in out[0].message
    assert "double-count" in out[0].message


def test_a_source_note_without_the_marker_yields_nothing():
    plain = SourceRecord(source_id="tf-plan", kind="tfplan-prior", scope="partial",
                         note="read arm 1 (prior_state.values.root_module)")
    assert drift.drift_verdicts(_ledger(sources=(plain,))) == ()


# -- carried through ----------------------------------------------------------


def test_a_key_mismatch_verdict_is_carried_through_verbatim():
    mismatch = Verdict(
        "unverified", merge.KEY_MISMATCH_KIND, "firewall_rules", 0,
        "sources 'tf-state' and 'api-capture' each contributed to 'firewall_rules' "
        "(3 and 4 keys) and zero keys matched")
    out = drift.drift_verdicts(_ledger(), verdicts=(mismatch,))
    assert out == (mismatch,)
    assert out[0].kind == "drift:key-mismatch"


def test_a_require_agreement_escalation_stays_contradicted_under_annotate():
    escalation = Verdict("contradicted", drift.DRIFT_MATERIAL,
                         f"firewall_rules/{RULE}", 0,
                         "precedence 'require-agreement' requires the sources to agree")
    out = drift.drift_verdicts(_ledger(), policy="annotate", verdicts=(escalation,))
    assert [(v.status, v.kind) for v in out] == [("contradicted", "drift:material")]


# -- the cap ------------------------------------------------------------------


def test_the_cap_is_fair_and_never_drops_the_first_verdict_of_a_kind():
    flood = tuple(
        Dispute(category="firewall_rules", key=f"k{i:03d}", field="description",
                severity="benign", left="'a'", right="'b'",
                reason="the sources disagree about 'description'")
        for i in range(drift.MAX_DRIFT_VERDICTS + 10))
    rare = Dispute(category="iam_bindings", key="//zzz", field="",
                   severity="unmergeable", left="tf-state", right="",
                   reason="the two views cannot be compared at all")
    out = drift.drift_verdicts(_ledger(disputes=flood + (rare,)))

    kinds = _kinds(out)
    # THE POINT: a naive head-truncation of the sorted list keeps 50 'drift'
    # verdicts and drops the only 'drift:unmergeable' one.
    assert kinds.count("drift:unmergeable") == 1
    assert len(out) == drift.MAX_DRIFT_VERDICTS + 1        # + the summary
    summary = out[-1]
    assert summary.kind == "drift"
    assert summary.target == "drift"
    assert "11 further drift verdict(s) were not listed" in summary.message
    assert "'drift'" in summary.message                    # which kind truncated
    assert "drift:unmergeable" not in summary.message      # it was not truncated


def test_nothing_is_capped_when_everything_fits():
    disputes = tuple(
        Dispute(category="firewall_rules", key=f"k{i}", field="description",
                severity="benign", left="'a'", right="'b'", reason="benign")
        for i in range(3))
    out = drift.drift_verdicts(_ledger(disputes=disputes))
    assert len(out) == 3
    assert all("were not listed" not in v.message for v in out)


# -- status -------------------------------------------------------------------


def _every_shape_ledger() -> SourceLedger:
    plan = SourceRecord(source_id="tf-plan", kind="tfplan-prior", scope="partial",
                        note=PLAN_DRIFT_NOTE)
    disputes = (
        Dispute(category="firewall_rules", key=RULE, field="priority",
                severity="material", left="1000", right="900", reason="disagree"),
        Dispute(category="firewall_rules", key=RULE, field="description",
                severity="benign", left="'a'", right="'b'", reason="disagree"),
        Dispute(category="firewall_rules", key="legacy", field="",
                severity="unmergeable", left="tf-state", right="", reason="raw key"),
        Dispute(category="firewall_rules", key=OTHER, field="", severity="unmanaged",
                left="api-capture", right="tf-state", reason="unmanaged"),
        _existence_dispute(),
    )
    return _ledger(sources=(API, TFSTATE, plan), disputes=disputes)


@pytest.mark.parametrize("policy", ["annotate", "abstain"])
def test_every_drift_verdict_is_unverified_under_annotate_and_abstain(policy):
    out = drift.drift_verdicts(_every_shape_ledger(), policy=policy)
    assert set(_kinds(out)) == {"drift", "drift:material", "drift:unmanaged",
                                "drift:unmergeable"}
    assert len(out) == 6      # two material shapes, benign, unmergeable,
                              # unmanaged and terraform's own resource_drift
    assert {v.status for v in out} == {"unverified"}


def test_only_drift_material_becomes_contradicted_under_block():
    out = drift.drift_verdicts(_every_shape_ledger(), policy="block")
    contradicted = {v.kind for v in out if v.status == "contradicted"}
    assert contradicted == {"drift:material"}
    # ...and every drift:material verdict is one, so the grading is total.
    assert all(v.status == "contradicted"
               for v in out if v.kind == "drift:material")
    assert all(v.status == "unverified"
               for v in out if v.kind != "drift:material")


def test_an_unrecognised_policy_falls_back_to_the_default_without_raising():
    out = drift.drift_verdicts(_every_shape_ledger(), policy="explode")
    assert {v.status for v in out} == {"unverified"}


# -- adjudicate: rule 1, the grounded downgrade -------------------------------


def _tainted_snapshot() -> ReconciledSnapshot:
    ledger = _ledger(
        sources=(API, TFSTATE),
        categories={"firewall_rules": CategoryScope(scope="complete",
                                                    source_kinds=("api",))},
        facts={"firewall_rules": {
            RULE: FactOrigin(source_id="tf-state", locator="a", taint="disputed"),
            OTHER: FactOrigin(source_id="api-capture", locator="b")}})
    return _snapshot(ledger)


@pytest.mark.parametrize("policy", ["annotate", "block", "abstain"])
def test_a_grounded_on_a_tainted_key_is_downgraded_under_every_policy(policy):
    snapshot = _tainted_snapshot()
    verdict = Verdict("grounded", "firewall", RULE, 0, "the rule is reachable")
    out = drift.adjudicate((verdict,), [("firewall_rules", RULE)], snapshot, policy)
    assert [v.status for v in out] == ["unverified"]
    assert out[0].kind == "firewall" and out[0].target == RULE
    assert "[not decided:" in out[0].message
    assert RULE in out[0].message and "disputed" in out[0].message


def test_a_grounded_on_an_untainted_sibling_key_is_left_alone():
    snapshot = _tainted_snapshot()
    verdict = Verdict("grounded", "firewall", OTHER, 0, "the rule is reachable")
    out = drift.adjudicate((verdict,), [("firewall_rules", OTHER)], snapshot,
                           "annotate")
    assert out == (verdict,)


def test_adjudicate_over_a_plain_snapshot_returns_the_verdicts_untouched():
    verdicts = (Verdict("grounded", "firewall", RULE, 0, "reachable"),)
    out = drift.adjudicate(verdicts, [("firewall_rules", RULE)],
                           GcpSnapshot(captured_at=CAPTURED), "abstain")
    assert out == verdicts


# -- adjudicate: rules 2 and 3, contradicted ----------------------------------


def _field_dispute_snapshot() -> ReconciledSnapshot:
    dispute = Dispute(category="firewall_rules", key=RULE, field="priority",
                      severity="material", left="1000", right="900",
                      reason="the sources disagree about 'priority'")
    ledger = _ledger(sources=(API, TFSTATE), disputes=(dispute,))
    return _snapshot(ledger, disputes=(dispute,))


@pytest.mark.parametrize("policy", ["annotate", "block"])
def test_a_contradicted_on_a_field_value_dispute_keeps_its_status(policy):
    snapshot = _field_dispute_snapshot()
    verdict = Verdict("contradicted", "firewall", RULE, 0, "this widens ingress")
    out = drift.adjudicate((verdict,), [("firewall_rules", RULE)], snapshot, policy)
    assert out == (verdict,)


def test_a_contradicted_on_a_field_value_dispute_flips_under_abstain():
    snapshot = _field_dispute_snapshot()
    verdict = Verdict("contradicted", "firewall", RULE, 0, "this widens ingress")
    out = drift.adjudicate((verdict,), [("firewall_rules", RULE)], snapshot,
                           "abstain")
    assert [v.status for v in out] == ["unverified"]
    assert "abstain" in out[0].message
    assert "universal suppressor" in out[0].message


# -- adjudicate: the carve-out, and its boundary ------------------------------


def _phantom_snapshot() -> ReconciledSnapshot:
    dispute = _existence_dispute()
    ledger = _ledger(sources=(API, TFSTATE), disputes=(dispute,))
    return _snapshot(ledger, disputes=(dispute,))


def test_a_contradicted_resting_only_on_a_phantom_fact_is_downgraded():
    snapshot = _phantom_snapshot()
    verdict = Verdict("contradicted", "firewall", RULE, 0,
                      "this rule is unreachable behind a higher-priority deny")
    out = drift.adjudicate((verdict,), [("firewall_rules", RULE)], snapshot,
                           "annotate")
    assert [v.status for v in out] == ["unverified"]
    message = out[0].message
    assert RULE in message                       # the phantom fact
    assert "tf-state" in message                 # both sources, by name
    assert "api-capture" in message
    assert "PHANTOM" in message


def test_the_same_contradicted_keeps_its_status_with_one_undisputed_fact():
    # THE BOUNDARY the carve-out is only sound because of: one fact nobody
    # disputes is enough evidence to keep the finding.
    snapshot = _phantom_snapshot()
    verdict = Verdict("contradicted", "firewall", RULE, 0,
                      "this rule is unreachable behind a higher-priority deny")
    out = drift.adjudicate(
        (verdict,), [("firewall_rules", RULE), ("firewall_rules", OTHER)],
        snapshot, "annotate")
    assert out == (verdict,)


def test_the_carve_out_needs_a_complete_source_asserting_absence():
    # The refuting source is PARTIAL, so absence from it is not evidence and the
    # finding stands.
    dispute = _existence_dispute()
    partial = SourceRecord(source_id="api-capture", kind="api", scope="partial")
    ledger = _ledger(sources=(partial, TFSTATE), disputes=(dispute,))
    snapshot = _snapshot(ledger, disputes=(dispute,))
    verdict = Verdict("contradicted", "firewall", RULE, 0, "unreachable")
    out = drift.adjudicate((verdict,), [("firewall_rules", RULE)], snapshot,
                           "annotate")
    assert out == (verdict,)


# -- adjudicate: rules 4 and 5 ------------------------------------------------


@pytest.mark.parametrize("policy", ["annotate", "block", "abstain"])
def test_an_ungrounded_is_always_downgraded(policy):
    snapshot = _snapshot(_ledger())
    verdict = Verdict("ungrounded", "firewall", RULE, 0, "no such rule",
                      suggestions=("a", "b"))
    out = drift.adjudicate((verdict,), [], snapshot, policy)
    assert [v.status for v in out] == ["unverified"]
    assert out[0].suggestions == ("a", "b")
    assert "PROVES" in out[0].message


def test_an_unverified_is_unchanged():
    snapshot = _tainted_snapshot()
    verdict = Verdict("unverified", "firewall", RULE, 0, "not decided offline")
    out = drift.adjudicate((verdict,), [("firewall_rules", RULE)], snapshot,
                           "abstain")
    assert out == (verdict,)


# -- guarded ------------------------------------------------------------------


def test_guarded_over_a_plain_snapshot_pushes_no_read_set(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("guarded must not open a read set for a plain "
                             "GcpSnapshot — that is the zero-overhead promise")

    monkeypatch.setattr(drift, "reads", explode)
    verdicts = (Verdict("grounded", "firewall", RULE, 0, "reachable"),)
    result = drift.guarded(lambda: verdicts, GcpSnapshot(captured_at=CAPTURED),
                           "annotate")
    assert result is verdicts                     # the IDENTICAL object
    assert reconciled.active_reads() == ()


def test_guarded_adjudicates_over_a_reconciled_snapshot():
    snapshot = _tainted_snapshot()

    def provider():
        snapshot.firewall_rule(RULE)              # the tap records this read
        return (Verdict("grounded", "firewall", RULE, 0, "reachable"),)

    out = drift.guarded(provider, snapshot, "annotate")
    assert [v.status for v in out] == ["unverified"]
    assert reconciled.active_reads() == ()


@pytest.mark.parametrize("snapshot_factory", [
    lambda: GcpSnapshot(captured_at=CAPTURED),
    lambda: _tainted_snapshot(),
])
def test_an_exception_propagates_through_guarded_untouched(snapshot_factory):
    sentinel = RuntimeError("the provider exploded")

    def provider():
        raise sentinel

    with pytest.raises(RuntimeError) as caught:
        drift.guarded(provider, snapshot_factory(), "annotate")
    assert caught.value is sentinel
    assert reconciled.active_reads() == ()        # and the stack unwound


# -- postpass -----------------------------------------------------------------


def _report(*verdicts: Verdict) -> GroundingReport:
    report = GroundingReport()
    for verdict in verdicts:
        report.add(verdict)
    return report


ROLE = "roles/acme.legacyAdmin"
SIBLING_ROLE = "roles/acme.otherAdmin"


def _ungrounded_role() -> Verdict:
    return Verdict("ungrounded", "role", ROLE, 0,
                   f"$.bindings[0].role: role '{ROLE}' does not exist in the "
                   f"snapshot (captured {CAPTURED})", suggestions=(SIBLING_ROLE,))


@pytest.mark.parametrize("scope,kind", [("partial", "tfstate"),
                                        ("undeclared", "hcl"),
                                        ("uncaptured", "hcl")])
def test_postpass_rule_1_downgrades_an_ungrounded_on_an_incomplete_category(
        scope, kind):
    ledger = _ledger(categories={"roles": CategoryScope(scope=scope,
                                                        source_kinds=(kind,))})
    report = _report(_ungrounded_role())
    drift.postpass(report, _snapshot(ledger), "annotate")
    assert [v.status for v in report.verdicts] == ["unverified"]
    message = report.verdicts[0].message
    assert "'roles'" in message                    # the category
    assert scope in message                        # its scope
    assert kind in message                         # the source that supplied it
    assert "a partial enumeration proves no absence" in message
    assert report.verdicts[0].suggestions == (SIBLING_ROLE,)


def test_postpass_rule_1_covers_declared_not_applied_with_its_own_reason():
    # The category is COMPLETE, so only the declared-not-applied set can explain
    # this one — which is why it is checked first.
    ledger = _ledger(categories={"roles": CategoryScope(scope="complete",
                                                        source_kinds=("api",))})
    report = _report(_ungrounded_role())
    drift.postpass(report, _snapshot(ledger), "annotate",
                   declared_not_applied={"roles": (ROLE,)})
    assert [v.status for v in report.verdicts] == ["unverified"]
    assert merge.DECLARED_NOT_APPLIED_REASON in report.verdicts[0].message
    assert ROLE in report.verdicts[0].message


def test_postpass_rule_2_downgrades_an_ungrounded_whose_own_key_is_disputed():
    dispute = Dispute(category="roles", key=ROLE, field="", severity="material",
                      left="tf-state", right="api-capture",
                      reason="present in one view and absent from the other")
    ledger = _ledger(sources=(API, TFSTATE),
                     categories={"roles": CategoryScope(scope="complete",
                                                        source_kinds=("api",))},
                     disputes=(dispute,))
    report = _report(_ungrounded_role())
    drift.postpass(report, _snapshot(ledger, disputes=(dispute,)), "annotate")
    assert [v.status for v in report.verdicts] == ["unverified"]
    message = report.verdicts[0].message
    assert ROLE in message
    assert "disputed" in message


def test_postpass_rule_3_leaves_alone_an_ungrounded_whose_sibling_is_disputed():
    """THE RULE THAT MUST NOT FIRE.

    An existence disagreement about X is evidence about X. Demoting the whole
    category on any single dispute would let one stale terraform file switch
    off hallucination detection entirely, which is this tool's primary value.
    """
    sibling = Dispute(category="roles", key=SIBLING_ROLE, field="",
                      severity="material", left="tf-state", right="api-capture",
                      reason="present in one view and absent from the other")
    ledger = _ledger(sources=(API, TFSTATE),
                     categories={"roles": CategoryScope(scope="complete",
                                                        source_kinds=("api",))},
                     disputes=(sibling,))
    original = _ungrounded_role()
    report = _report(original)
    drift.postpass(report, _snapshot(ledger, disputes=(sibling,)), "annotate")
    assert report.verdicts == [original]
    assert report.verdicts[0].status == "ungrounded"


def test_postpass_rebuilds_the_list_in_the_same_order():
    ledger = _ledger(categories={"roles": CategoryScope(scope="partial",
                                                        source_kinds=("tfstate",))})
    grounded = Verdict("grounded", "permission", "iam.roles.get", 0, "exists")
    unverified = Verdict("unverified", "cel", "expr", 0, "not decided")
    report = _report(grounded, _ungrounded_role(), unverified)
    drift.postpass(report, _snapshot(ledger), "annotate")
    assert [v.kind for v in report.verdicts] == ["permission", "role", "cel"]
    assert report.verdicts[0] == grounded          # untouched
    assert report.verdicts[2] == unverified        # untouched
    assert report.verdicts[1].status == "unverified"


def test_postpass_over_a_plain_snapshot_changes_nothing():
    original = _ungrounded_role()
    report = _report(original)
    drift.postpass(report, GcpSnapshot(captured_at=CAPTURED), "annotate")
    assert report.verdicts == [original]


def test_postpass_ignores_a_verdict_kind_that_names_no_category():
    ledger = _ledger(categories={"roles": CategoryScope(scope="partial",
                                                        source_kinds=("tfstate",))})
    original = Verdict("ungrounded", "subset", "iam-policy", 0, "new is not a subset")
    report = _report(original)
    drift.postpass(report, _snapshot(ledger), "annotate")
    assert report.verdicts == [original]
