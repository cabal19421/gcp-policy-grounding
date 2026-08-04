"""Evidence-channel tests: the typed abstain, the collection-read contract and
the per-invocation ledger.

The asymmetry is the property under test. Every unknown shape must ABSTAIN —
an absent key, a dict where a list belongs, a string, ``None`` — and each
abstention must name the container it could not read and the type it got
instead. The only paths that yield "nothing to see here" are the two explicit
ones: a key that is PRESENT and holds an empty list, and a caller who calls
:func:`emptiness_is_dispositive` with a reason a reviewer can read. Silence is
never one of them: a read outside a ledger is a programming error, not a quiet
success, and a raising check leaves no ledger behind for the next invocation.
"""

import re

import pytest

from gcp_grounding.evidence import (
    Extraction,
    Ledger,
    NotEvaluated,
    emptiness_is_dispositive,
    examined,
    ledger,
    observed_empty,
    rows,
    scalar,
)

#: A hierarchical-firewall-shaped document: one readable list, one empty list,
#: one field of the wrong shape, and one absent key ("rules" is never present).
FIREWALL = {
    "name": "fp-baseline",
    "priority": 1000,
    "associations": [{"name": "assoc-a"}, {"name": "assoc-b"}],
    "exceptions": [],
    "rule_summary": {"count": 3},
}

WHAT = "hierarchical firewall policy 'fp-baseline'"


# ── the typed abstain ─────────────────────────────────────────────────────────

def test_not_evaluated_carries_what_and_reason_and_renders_both():
    exc = NotEvaluated(WHAT, "has no readable 'rules' list, got dict")
    assert exc.what == WHAT
    assert exc.reason == "has no readable 'rules' list, got dict"
    assert WHAT in str(exc)
    assert "has no readable 'rules' list, got dict" in str(exc)


def test_not_evaluated_is_an_exception_not_a_verdict():
    # It must propagate out of a check, so the invoker can rewrite the whole
    # check to `unverified`; a truthy return value would be swallowed.
    assert issubclass(NotEvaluated, Exception)
    with pytest.raises(NotEvaluated):
        raise NotEvaluated(WHAT, "never looked")


# ── rows(): the only sanctioned collection read ───────────────────────────────

def test_rows_raises_for_an_absent_key():
    with ledger():
        with pytest.raises(NotEvaluated) as caught:
            rows(FIREWALL, "rules", what=WHAT)
    exc = caught.value
    assert exc.what == WHAT
    assert "'rules'" in exc.reason
    assert WHAT in str(exc)


@pytest.mark.parametrize(
    "value, type_name",
    [
        ("rule-a,rule-b", "str"),          # a string is iterable — the trap
        ({"count": 3}, "dict"),            # a Mapping is not a collection of rows
        (None, "NoneType"),                # captured, but as nothing
        (7, "int"),
        (("rule-a",), "tuple"),            # JSON never yields one; not a list
        (set(), "set"),
    ],
)
def test_rows_raises_for_every_non_list_value_naming_the_type(value, type_name):
    document = dict(FIREWALL, rules=value)
    with ledger():
        with pytest.raises(NotEvaluated) as caught:
            rows(document, "rules", what=WHAT)
    exc = caught.value
    assert exc.what == WHAT
    assert "'rules'" in exc.reason
    assert type_name in exc.reason, f"the offending type must be named: {exc.reason!r}"
    assert type_name in str(exc)


def test_rows_raises_when_the_container_itself_is_not_a_mapping():
    with ledger():
        with pytest.raises(NotEvaluated) as caught:
            rows(["not", "a", "mapping"], "rules", what=WHAT)
    assert "list" in caught.value.reason


def test_rows_returns_the_records_of_a_present_list():
    with ledger() as led:
        got = rows(FIREWALL, "associations", what=WHAT)
    assert got == ({"name": "assoc-a"}, {"name": "assoc-b"})
    assert isinstance(got, tuple)
    assert led.empty_observed == ()


def test_rows_returns_empty_and_records_empty_observed_for_a_present_empty_list():
    with ledger() as led:
        got = rows(FIREWALL, "exceptions", what=WHAT)
    assert got == ()
    assert len(led.empty_observed) == 1
    note = led.empty_observed[0]
    assert WHAT in note and "'exceptions'" in note
    # A positively observed empty still counts as a collection that was read.
    assert led.collections_read == 1
    assert led.rows_examined == 0


def test_an_abstained_read_never_lands_in_empty_observed():
    with ledger() as led:
        with pytest.raises(NotEvaluated):
            rows(FIREWALL, "rules", what=WHAT)
    assert led.empty_observed == ()


# ── the ledger ────────────────────────────────────────────────────────────────

def test_ledger_counts_reads_and_rows_across_several_calls():
    document = dict(FIREWALL, rules=[{"action": "allow"}, {"action": "deny"},
                                     {"action": "goto_next"}])
    with ledger() as led:
        assert (led.collections_read, led.rows_examined) == (0, 0)
        rows(document, "rules", what=WHAT)
        assert (led.collections_read, led.rows_examined) == (1, 3)
        rows(document, "associations", what=WHAT)
        assert (led.collections_read, led.rows_examined) == (2, 5)
        rows(document, "exceptions", what=WHAT)
        assert (led.collections_read, led.rows_examined) == (3, 5)
        assert led.dispositive is None


def test_a_read_that_abstains_still_counts_as_a_collection_read():
    # "collections read above zero, rows examined at zero" is the funnel's
    # signal for a check that looked and saw nothing — an attempted read that
    # blew up must not erase the attempt.
    with ledger() as led:
        with pytest.raises(NotEvaluated):
            rows(FIREWALL, "rule_summary", what=WHAT)
    assert led.collections_read == 1
    assert led.rows_examined == 0


def test_examined_counts_rows_reached_through_a_snapshot_accessor():
    with ledger() as led:
        examined(4, what="snapshot.firewall_rules")
        assert (led.collections_read, led.rows_examined) == (1, 4)
        examined(0, what="snapshot.org_policies")
        assert (led.collections_read, led.rows_examined) == (2, 4)
    # Zero rows out of an accessor is the same positive observation rows()
    # records for a present empty list.
    assert any("snapshot.org_policies" in note for note in led.empty_observed)


def test_examined_rejects_a_negative_or_non_integer_count():
    with ledger():
        with pytest.raises(ValueError):
            examined(-1, what="snapshot.firewall_rules")
        with pytest.raises(TypeError):
            examined("4", what="snapshot.firewall_rules")


def test_nested_ledger_opens_are_an_error_not_a_silent_reset():
    with ledger() as outer:
        rows(FIREWALL, "associations", what=WHAT)
        with pytest.raises(RuntimeError) as caught:
            with ledger():
                pass
        assert "ledger" in str(caught.value).lower()
        # The outer ledger survived the attempt intact.
        assert (outer.collections_read, outer.rows_examined) == (1, 2)


def test_rows_outside_a_ledger_is_a_programming_error_not_a_silent_success():
    with pytest.raises(RuntimeError) as caught:
        rows(FIREWALL, "associations", what=WHAT)
    assert not isinstance(caught.value, NotEvaluated), (
        "an unopened ledger is the invoker's bug, never the document's abstain")
    assert "ledger" in str(caught.value).lower()


@pytest.mark.parametrize("call", [
    lambda: rows(FIREWALL, "associations", what=WHAT),
    lambda: examined(2, what="snapshot.firewall_rules"),
    lambda: emptiness_is_dispositive("nothing to see"),
])
def test_every_ledger_write_refuses_to_run_unbound(call):
    with pytest.raises(RuntimeError):
        call()


def test_a_raising_body_leaves_no_ledger_bound():
    boom = RuntimeError("check blew up mid-flight")
    with pytest.raises(RuntimeError) as caught:
        with ledger():
            rows(FIREWALL, "associations", what=WHAT)
            raise boom
    assert caught.value is boom

    # The finally-reset is what this proves: the next invocation must find no
    # ledger at all, rather than inheriting the dead one's counts.
    with pytest.raises(RuntimeError) as unbound:
        rows(FIREWALL, "associations", what=WHAT)
    assert "ledger" in str(unbound.value).lower()

    with ledger() as fresh:
        assert (fresh.collections_read, fresh.rows_examined) == (0, 0)
        assert fresh.empty_observed == ()
        assert fresh.dispositive is None


def test_each_ledger_is_a_fresh_object():
    with ledger() as first:
        rows(FIREWALL, "associations", what=WHAT)
    with ledger() as second:
        pass
    assert first is not second
    assert isinstance(second, Ledger)
    assert second.rows_examined == 0


# ── emptiness_is_dispositive: the one explicit knob ───────────────────────────

def test_emptiness_is_dispositive_records_its_reason():
    reason = ("the policy captured all 3 levels and every level's rule list is "
              "present and empty, so no packet is decided")
    with ledger() as led:
        rows(FIREWALL, "exceptions", what=WHAT)
        emptiness_is_dispositive(reason)
        assert led.dispositive == reason
    assert led.dispositive == reason


def test_emptiness_is_dispositive_refuses_an_empty_reason():
    # "grounding over nothing takes one explicit call whose string a reviewer
    # can read" — a blank string is not a reason.
    with ledger() as led:
        for blank in ("", "   "):
            with pytest.raises(ValueError):
                emptiness_is_dispositive(blank)
        assert led.dispositive is None


# ── Extraction: the extraction contract ───────────────────────────────────────

def test_extraction_defaults_to_never_looked():
    got = Extraction()
    assert got.records == ()
    assert got.empty_because is None
    assert got.missing_reason, "a caller who says nothing must get a reason synthesized"


def test_extraction_synthesizes_a_missing_reason_for_a_forgetful_caller():
    got = Extraction()
    assert re.search(r"no records|nothing|not.*(read|examin)", got.missing_reason, re.I), (
        f"synthesized reason must say what it means: {got.missing_reason!r}")


def test_extraction_keeps_an_explicit_missing_reason():
    got = Extraction(missing_reason="the 'rules' key was absent")
    assert got.missing_reason == "the 'rules' key was absent"
    assert got.empty_because is None


def test_extraction_with_records_needs_no_reason():
    got = Extraction(records=({"action": "allow"},))
    assert got.records == ({"action": "allow"},)
    assert got.missing_reason is None
    assert got.empty_because is None


def test_extraction_rejects_records_together_with_a_missing_reason():
    # UNREADABLE and "here are the records" cannot both be true.
    with pytest.raises(ValueError) as caught:
        Extraction(records=({"action": "allow"},),
                   missing_reason="has no readable 'rules' list, got dict")
    assert "missing_reason" in str(caught.value)


def test_extraction_rejects_records_together_with_empty_because():
    with pytest.raises(ValueError):
        Extraction(records=({"action": "allow"},), empty_because="present and empty")


def test_extraction_rejects_both_reasons_at_once():
    # UNREADABLE and POSITIVELY EMPTY are different states of the world.
    with pytest.raises(ValueError):
        Extraction(missing_reason="never looked", empty_because="present and empty")


def test_extraction_is_frozen():
    got = Extraction(records=({"action": "allow"},))
    with pytest.raises(Exception):
        got.records = ()


def test_extraction_coerces_a_list_of_records_to_a_tuple():
    got = Extraction(records=[{"action": "allow"}])
    assert got.records == ({"action": "allow"},)


@pytest.mark.parametrize("bad", ["allow", {"action": "allow"}, None, 3])
def test_extraction_rejects_records_that_are_not_a_sequence(bad):
    with pytest.raises(TypeError):
        Extraction(records=bad)


def test_observed_empty_builds_a_positively_empty_extraction():
    got = observed_empty(WHAT, "'exceptions' is present and holds no rules")
    assert got.records == ()
    assert got.missing_reason is None
    assert WHAT in got.empty_because
    assert "'exceptions' is present and holds no rules" in got.empty_because


def test_observed_empty_refuses_an_empty_detail():
    with pytest.raises(ValueError):
        observed_empty(WHAT, "")


# ── scalar(): typed single fields ─────────────────────────────────────────────

def test_scalar_returns_a_correctly_typed_field():
    with ledger():
        assert scalar(FIREWALL, "name", what=WHAT, type=str) == "fp-baseline"
        assert scalar(FIREWALL, "priority", what=WHAT, type=int) == 1000


def test_scalar_raises_for_a_wrong_type_naming_both_types():
    with pytest.raises(NotEvaluated) as caught:
        scalar(FIREWALL, "priority", what=WHAT, type=str)
    reason = caught.value.reason
    assert "'priority'" in reason
    assert "str" in reason and "int" in reason


def test_scalar_raises_for_an_absent_key_by_default():
    with pytest.raises(NotEvaluated) as caught:
        scalar(FIREWALL, "direction", what=WHAT, type=str)
    assert "'direction'" in caught.value.reason
    assert caught.value.what == WHAT


def test_scalar_returns_an_explicit_default_for_an_absent_key():
    assert scalar(FIREWALL, "direction", what=WHAT, type=str, absent="INGRESS") == "INGRESS"
    assert scalar(FIREWALL, "direction", what=WHAT, type=str, absent=None) is None


def test_scalar_default_does_not_excuse_a_wrong_type():
    # The key is there and the shape is wrong: that is unreadable, not absent.
    with pytest.raises(NotEvaluated):
        scalar(FIREWALL, "priority", what=WHAT, type=str, absent="fallback")


def test_scalar_rejects_a_bool_where_an_int_is_expected():
    document = dict(FIREWALL, priority=True)
    with pytest.raises(NotEvaluated) as caught:
        scalar(document, "priority", what=WHAT, type=int)
    assert "bool" in caught.value.reason


def test_scalar_accepts_a_bool_when_a_bool_is_expected():
    document = dict(FIREWALL, enabled=False)
    assert scalar(document, "enabled", what=WHAT, type=bool) is False


def test_scalar_raises_when_the_container_is_not_a_mapping():
    with pytest.raises(NotEvaluated) as caught:
        scalar(["fp-baseline"], "name", what=WHAT, type=str)
    assert "list" in caught.value.reason


def test_scalar_needs_no_ledger():
    # A single typed field is not a collection read; it must stay usable in
    # helpers that run outside an invocation.
    assert scalar(FIREWALL, "name", what=WHAT, type=str) == "fp-baseline"


# ── the leaf contract ─────────────────────────────────────────────────────────

def test_evidence_is_a_leaf_importing_only_core_log():
    import gcp_grounding.evidence as module

    source = __import__("pathlib").Path(module.__file__).read_text(encoding="utf-8")
    package_imports = set(re.findall(r"^\s*from\s+(\.[\w.]*|gcp_grounding[\w.]*)",
                                     source, re.M))
    package_imports |= set(re.findall(r"^\s*import\s+(gcp_grounding[\w.]*)",
                                      source, re.M))
    assert package_imports <= {".core.log"}, (
        f"evidence.py must stay a leaf; it imports {sorted(package_imports)}")
    assert "z3" not in re.findall(r"^\s*import\s+(\w+)", source, re.M)
