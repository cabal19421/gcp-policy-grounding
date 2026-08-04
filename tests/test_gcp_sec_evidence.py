"""Witness side-table and ``sec`` document tests.

The contract under test is composition: :func:`sec_evidence.sec_document`
reproduces everything :meth:`PolicyReport.to_dict` produced, adds EXACTLY ONE
top-level key (``"sec"``), always emits it — empty lists rather than an absent
key when nothing loaded — never mutates its input, and is byte-deterministic.
Plus the row ordering and the ``--explain`` rendering.

No z3 anywhere: the promises are hand-built with literal sexpr strings, which
is the point of the artifact being pure data.
"""

import json
from dataclasses import dataclass

import pytest

from gcp_grounding.core.report import GroundingReport, Verdict
from gcp_grounding.report import SCHEMA, PolicyReport
from gcp_grounding.sec_artifact import Promise, Source, Wellformedness, Witness
from gcp_grounding.sec_evidence import (
    SEC_REPORT_SCHEMA,
    WITNESS_ROLES,
    WitnessRow,
    WitnessTable,
    explain_lines,
    sec_document,
)

CAPTURED = "2026-07-18T09:30:00Z"

#: A faithful ``sec_ast`` shape (never validated here — Promise stores the ast
#: as data), so the fixture reads like a real compiled promise.
_NO_ALL_USERS_AST = {
    "node": "forall", "var": "b", "collection": "iam_bindings",
    "body": {"node": "not", "arg": {
        "node": "cmp", "op": "eq",
        "left": {"node": "field", "var": "b", "field": "member"},
        "right": {"node": "lit", "sort": "Str", "value": "allUsers"}}},
}


def promise(pid: str, **overrides) -> Promise:
    """One compiled promise with hand-written sexpr and pinned witnesses."""
    kwargs = dict(
        id=pid,
        source=Source(file="sec_requirements/iam.md", line=12,
                      text="No IAM binding may grant a role to allUsers."),
        domain="iam",
        mode="refute",
        state="proposal",
        severity="high",
        ast=_NO_ALL_USERS_AST,
        sexpr="(not (= iam_bindings#b.member \"allUsers\"))",
        positive=Witness({"iam_bindings#b.member": "user:alice@acme.example",
                          "iam_bindings#b.role": "roles/viewer"}, "z3-model"),
        negative=Witness({"iam_bindings#b.role": "roles/editor",
                          "iam_bindings#b.member": "allUsers"}, "pinned"),
        wellformedness=Wellformedness(satisfiable=True, non_tautological=True),
        status="compiled",
    )
    kwargs.update(overrides)
    return Promise(**kwargs)


@dataclass(frozen=True)
class _Rule:
    """A ``CompiledRule``-shaped wrapper: ``sec_document`` / ``explain_lines``
    take the loaded rule or its bare promise."""

    promise: Promise


@pytest.fixture()
def report() -> PolicyReport:
    grounding = GroundingReport()
    grounding.add(Verdict("grounded", "sec:iam", "no-public-iam", 0,
                          "no-public-iam: the obligation holds over the document"))
    grounding.add(Verdict("contradicted", "sec:iam", "no-public-editor", 0,
                          "no-public-editor: refuted by iam_bindings[1] "
                          "member='allUsers' role='roles/editor'"))
    return PolicyReport(grounding, captured_at=CAPTURED, source="x.json")


@pytest.fixture()
def table() -> WitnessTable:
    t = WitnessTable()
    t.add(WitnessRow("no-public-editor", "violating-record",
                     collection="iam_bindings", index=1,
                     assignment={"role": "roles/editor", "member": "allUsers"}))
    t.add(WitnessRow("no-public-editor", "pinned-positive",
                     assignment={"iam_bindings#b.member": "user:alice@acme.example"}))
    t.add(WitnessRow("no-public-editor", "pinned-negative",
                     assignment={"iam_bindings#b.member": "allUsers"}))
    return t


@pytest.fixture()
def rules() -> tuple:
    return (_Rule(promise("no-public-editor")),
            _Rule(promise("no-public-iam", severity="medium")))


# -- composition: the base document survives byte for byte --------------------


def test_sec_document_preserves_every_base_key(report, table, rules):
    fresh = report.to_dict()
    doc = sec_document(report, table, rules)
    for key, value in fresh.items():
        assert doc[key] == value
    assert doc["schema"] == SCHEMA  # report.SCHEMA is NOT bumped
    assert list(doc)[:len(fresh)] == list(fresh)


def test_sec_document_adds_exactly_one_top_level_key(report, table, rules):
    doc = sec_document(report, table, rules)
    assert set(doc) - set(report.to_dict()) == {"sec"}
    assert set(doc["sec"]) == {"sec_schema", "witnesses", "requirements"}
    assert doc["sec"]["sec_schema"] == SEC_REPORT_SCHEMA == "gcp-sec-report/1"


def test_the_sec_key_is_present_even_with_nothing_loaded(report):
    doc = sec_document(report, WitnessTable())
    assert doc["sec"] == {"sec_schema": SEC_REPORT_SCHEMA,
                          "witnesses": [], "requirements": []}
    # The shape does not depend on whether rules happened to load.
    assert set(doc["sec"]) == set(sec_document(report, WitnessTable(),
                                               ((_Rule(promise("p"))),))["sec"])


def test_sec_document_does_not_mutate_its_input(report, table, rules):
    before = report.to_dict()
    doc = sec_document(report, table, rules)
    assert report.to_dict() == before
    assert "sec" not in before
    doc["sec"]["witnesses"].append("scribble")
    assert report.to_dict() == before

    mapping = report.to_dict()
    sec_document(mapping, table, rules)
    assert mapping == before


def test_sec_document_is_deterministic(report, table, rules):
    first = sec_document(report, table, rules)
    second = sec_document(report, table, tuple(reversed(rules)))
    assert first == second
    assert (json.dumps(first, sort_keys=True)
            == json.dumps(second, sort_keys=True))


# -- the requirements block ---------------------------------------------------


def test_requirements_carry_the_documented_fields_sorted_by_id(report, table, rules):
    entries = sec_document(report, table, rules)["sec"]["requirements"]
    assert [e["id"] for e in entries] == ["no-public-editor", "no-public-iam"]
    entry = entries[0]
    assert set(entry) == {"id", "source", "domain", "mode", "state",
                          "severity", "status", "sexpr"}
    assert entry["source"] == {"file": "sec_requirements/iam.md", "line": 12,
                               "text": "No IAM binding may grant a role to allUsers."}
    assert entry["domain"] == "iam"
    assert entry["mode"] == "refute"
    assert entry["state"] == "proposal"
    assert entry["severity"] == "high"
    assert entry["status"] == "compiled"
    assert entry["sexpr"] == "(not (= iam_bindings#b.member \"allUsers\"))"


def test_a_bare_promise_renders_like_a_loaded_rule(report, table, rules):
    wrapped = sec_document(report, table, rules)["sec"]["requirements"]
    bare = sec_document(report, table,
                        [r.promise for r in rules])["sec"]["requirements"]
    assert wrapped == bare


# -- the witness table --------------------------------------------------------


def test_rows_sort_by_promise_then_role_then_index():
    t = WitnessTable()
    rows = [
        WitnessRow("b-rule", "pinned-positive"),
        WitnessRow("a-rule", "violating-record", collection="iam_bindings", index=2),
        WitnessRow("a-rule", "violating-record", collection="iam_bindings", index=0),
        WitnessRow("a-rule", "pinned-positive"),
        WitnessRow("a-rule", "pinned-negative"),
    ]
    for row in rows:
        t.add(row)
    assert [(r.promise_id, r.role, r.index) for r in t.rows()] == [
        ("a-rule", "pinned-negative", -1),
        ("a-rule", "pinned-positive", -1),
        ("a-rule", "violating-record", 0),
        ("a-rule", "violating-record", 2),
        ("b-rule", "pinned-positive", -1),
    ]
    assert len(t) == 5


def test_pinned_rows_default_to_no_location():
    row = WitnessRow("a-rule", "pinned-positive")
    assert row.collection == ""
    assert row.index == -1
    assert row.assignment == {}


def test_to_list_is_json_data_with_sorted_assignment_keys(table):
    rows = table.to_list()
    assert [r["role"] for r in rows] == ["pinned-negative", "pinned-positive",
                                         "violating-record"]
    violating = rows[-1]
    assert violating == {"promise_id": "no-public-editor",
                         "role": "violating-record",
                         "collection": "iam_bindings", "index": 1,
                         "assignment": {"member": "allUsers",
                                        "role": "roles/editor"}}
    assert list(violating["assignment"]) == ["member", "role"]
    assert json.dumps(rows)  # every value is JSON data


def test_witness_row_rejects_an_unknown_role():
    assert WITNESS_ROLES == ("pinned-positive", "pinned-negative",
                             "violating-record")
    with pytest.raises(ValueError, match="witness role"):
        WitnessRow("a-rule", "counter-example")


def test_witness_row_rejects_a_non_string_assignment_value():
    with pytest.raises(ValueError, match="string literal"):
        WitnessRow("a-rule", "violating-record", collection="iam_bindings",
                   index=0, assignment={"has_condition": True})


def test_the_table_takes_only_witness_rows():
    with pytest.raises(TypeError):
        WitnessTable().add({"promise_id": "a-rule"})


# -- the --explain block ------------------------------------------------------


def test_explain_lines_render_the_documented_shape(rules):
    lines = explain_lines(rules)
    assert len(lines) == 6
    assert lines[0] == ("  [sec:iam] no-public-editor "
                        "(sec_requirements/iam.md:12): "
                        "(not (= iam_bindings#b.member \"allUsers\"))")
    assert lines[1] == ("      + compliant: "
                        "iam_bindings#b.member=user:alice@acme.example, "
                        "iam_bindings#b.role=roles/viewer")
    assert lines[2] == ("      - violating:  "
                        "iam_bindings#b.member=allUsers, "
                        "iam_bindings#b.role=roles/editor")
    assert lines[3].startswith("  [sec:iam] no-public-iam ")


def test_explain_lines_are_ordered_by_promise_id(rules):
    ids = [line.split("] ", 1)[1].split(" (", 1)[0]
           for line in explain_lines(tuple(reversed(rules)))
           if line.startswith("  [sec:")]
    assert ids == sorted(ids) == ["no-public-editor", "no-public-iam"]


def test_explain_lines_with_no_rules_say_so():
    assert explain_lines() == ["  (no compiled requirements were loaded)"]
    assert explain_lines(()) == ["  (no compiled requirements were loaded)"]


def test_explain_lines_never_fabricate_a_missing_witness():
    unverified = promise("not-compiled", status="unverified",
                         reason="the requirement named an unknown collection",
                         ast=None, sexpr="", positive=None, negative=None,
                         wellformedness=Wellformedness())
    _head, positive, negative = explain_lines([unverified])
    assert positive == "      + compliant: (no pinned witness)"
    assert negative == "      - violating:  (no pinned witness)"
