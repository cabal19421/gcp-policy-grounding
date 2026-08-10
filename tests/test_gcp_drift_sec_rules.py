"""Acceptance for drift adjudication inside `gcp_grounding.sec_rules`.

A compiled `sec_requirements/` promise evaluates OUTSIDE the check registry —
`preflight` calls `CompiledRule.evaluate` directly — so the two guards pinned
here are the only thing standing between a disputed or partial estate and a
confident `grounded` on the one rule a human wrote down by hand.

FOUR THINGS ARE PINNED, and each is easy to get subtly wrong.

ONE, THE TAINT ADJUDICATION IS PER-RECORD. A `grounded` that rests on a tainted
record is downgraded; the SAME rule with a DIFFERENT record tainted still
grounds. They are asserted side by side, because a downgrade that fires on any
taint anywhere would hand one stale terraform file a switch that turns every
promise into an abstain.

TWO, THE UNIVERSAL-NEGATIVE PIN. `sec_domains`' estate extractors honour only
the CAPTURED bit, and a terraform capture emits `firewall_rules` at scope
`partial` — captured, not UNKNOWN. So the abstention is asserted AS A PAIR with
the identical promise over a `complete` view, since an abstention that also
fires on a complete estate has not made the tool honest, only useless.

THREE, THE GATES ARE NOT ADJUDICATED. A non-applicable rule is still silent and
leaks no read context; a rule with a missing baseline still emits its OWN
`unverified` rather than one rewritten with the drift suffix.

FOUR, THE `sec:artifact` CARVE-OUT. An artifact-integrity verdict is a statement
about a committed file, so it is emitted unchanged even when every estate fact
it could touch is tainted — tainting it would let estate drift mask a
hand-edited promise.

Branched on the z3 availability boolean (the `HAVE_Z3` idiom) rather than
skipped, and the promise documents are built in code so nothing here depends on
the stage-1 compiler.
"""

from __future__ import annotations

import pytest

from gcp_grounding import drift, provenance, reconciled, sec_artifact, sec_ast, sec_rules
from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.report import Verdict
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.provenance import (
    CategoryScope,
    FactOrigin,
    SourceLedger,
    SourceRecord,
)
from gcp_grounding.reconciled import ReconciledSnapshot
from gcp_grounding.sec_ast import CollectionSpec

_SOLVER = get_solver()
Z3 = _z3_module(_SOLVER)
HAVE_Z3 = _SOLVER.backend == "z3"
BUILTIN = get_solver("builtin")

CAPTURED = "2026-01-01T00:00:00Z"

#: The estate-tier VPC firewall collection, spelled EXACTLY as
#: ``sec_domains.COLLECTION_SPECS`` spells it — `register_collection` is
#: idempotent for an identical spec, so this suite installs it in a checkout
#: without `sec_domains` and is a free no-op in one that has it.
FIREWALL_FIELDS = {
    "name": "Str",
    "network": "Str",
    "direction": "Str",
    "action": "Str",
    "priority": "Int",
    "disabled": "Bool",
    "source_range": "Cidr",
    "source_range_mask": "Ip4",
    "destination_range": "Cidr",
    "destination_range_mask": "Ip4",
    "source_tag": "Str",
    "target_tag": "Str",
    "protocol": "Proto",
    "port": "Port",
}
sec_ast.register_collection(CollectionSpec("firewall_rules", "estate", FIREWALL_FIELDS))


# -- the estate under test ----------------------------------------------------

HTTPS = "projects/acme-prod/global/firewalls/allow-https"
SSH = "projects/acme-prod/global/firewalls/allow-ssh-world"
EGRESS = "projects/acme-prod/global/firewalls/egress-all"

_EGRESS_ROW = {"direction": "EGRESS", "action": "allow", "port": 443}

#: No INGRESS rule opens tcp/22 — the promise below holds.
CLEAN_TABLE = {
    HTTPS: {"direction": "INGRESS", "action": "allow", "port": 443},
    EGRESS: dict(_EGRESS_ROW),
}
#: One INGRESS rule opens tcp/22 from anywhere — the promise below is refuted.
OPEN_TABLE = {
    SSH: {"direction": "INGRESS", "action": "allow", "port": 22},
    EGRESS: dict(_EGRESS_ROW),
}


def _row(name, record):
    """One flat record, every declared field present (``sec_encode`` abstains on
    a field the record omits)."""
    return {
        "name": name,
        "network": "projects/acme-prod/global/networks/vpc",
        "direction": record["direction"],
        "action": record["action"],
        "priority": 1000,
        "disabled": False,
        "source_range": "0.0.0.0/0",
        "source_range_mask": "0.0.0.0",
        "destination_range": "0.0.0.0/0",
        "destination_range_mask": "0.0.0.0",
        "source_tag": "",
        "target_tag": "",
        "protocol": 6,
        "port": record["port"],
    }


def _estate_extractor(ctx):
    """``firewall_rules`` records, reading the estate the way a domain extractor
    does: the raw field (a whole-category read, taped automatically) plus ONE
    keyed read per record it actually emits.

    An EGRESS rule is not this promise's business, so it is filtered out and
    NOT recorded as read — which is what makes "a different record is tainted"
    a different question from "the record this answer rests on is tainted".
    """
    table = ctx.snapshot.firewall_rules
    if table is None:
        return (), ("snapshot did not capture firewall_rules — the estate-tier "
                    "rule was not evaluated")
    rows = []
    for name in sorted(table):
        record = table[name]
        if record["direction"] != "INGRESS":
            continue
        reconciled.note_read("firewall_rules", name)
        rows.append(_row(name, record))
    return tuple(rows), None


@pytest.fixture(autouse=True)
def _isolate():
    saved = dict(sec_rules.EXTRACTORS)
    sec_rules.RULES.clear()
    sec_rules._LAST_WITNESS.clear()
    sec_rules.register_extractor("firewall_rules", _estate_extractor)
    yield
    sec_rules.RULES.clear()
    sec_rules._LAST_WITNESS.clear()
    sec_rules.EXTRACTORS.clear()
    sec_rules.EXTRACTORS.update(saved)
    assert reconciled.active_reads() == ()


# -- AST / promise builders ---------------------------------------------------

def _fld(name, var="r"):
    return {"node": "field", "var": var, "field": name}


def _lit(sort, value):
    return {"node": "lit", "sort": sort, "value": value}


def _cmp(op, left, right):
    return {"node": "cmp", "op": op, "left": left, "right": right}


#: "an INGRESS rule allows tcp/22" — the property a promise refutes.
OPEN_SSH = {"node": "and", "args": [
    _cmp("eq", _fld("direction"), _lit("Str", "INGRESS")),
    _cmp("eq", _fld("action"), _lit("Str", "allow")),
    _cmp("eq", _fld("port"), _lit("Port", 22)),
]}

#: refute: NO ingress firewall rule may allow tcp/22 from 0.0.0.0/0.
AST_REFUTE = {"node": "exists", "var": "r", "collection": "firewall_rules",
              "body": OPEN_SSH}

#: The same promise written as the UNIVERSALLY-QUANTIFIED NEGATIVE it is — the
#: shape that reads `grounded` off an empty sweep of a partial table.
AST_FORALL = {"node": "forall", "var": "r", "collection": "firewall_rules",
              "body": {"node": "not", "arg": OPEN_SSH}}

#: A pair-tier AST, for the missing-baseline gate.
AST_PAIR = {"node": "exists", "var": "o", "collection": "old_iam_bindings",
            "body": _cmp("eq", _fld("member", "o"), _lit("Str", "allUsers"))}


def _promise(pid, mode, ast, *, domain="vpc_firewall", state="estate",
            sexpr="(assert true)"):
    return sec_artifact.Promise(
        id=pid, source=sec_artifact.Source(file="req.md", line=3,
                                           text="no ingress rule may allow tcp/22"),
        domain=domain, mode=mode, state=state, severity="high", vocabulary=(),
        ast=ast, sexpr=sexpr, free_consts=(),
        positive=sec_artifact.Witness(assignment={"x": "1"}, origin="pinned"),
        negative=sec_artifact.Witness(assignment={"x": "0"}, origin="pinned"),
        wellformedness=sec_artifact.Wellformedness(satisfiable=True,
                                                   non_tautological=True),
        status="compiled", reason="")


def _rule(pid, mode, ast, **kwargs):
    return sec_rules.CompiledRule(promise=_promise(pid, mode, ast, **kwargs))


# -- snapshot builders --------------------------------------------------------

def _reconciled(table=CLEAN_TABLE, *, scope="complete", kind="api",
                fact_taints=(), category_taint=""):
    """A reconciled snapshot whose ``firewall_rules`` coverage and per-fact
    taints are exactly as declared."""
    source = SourceRecord(source_id=f"{kind}-capture", kind=kind, scope=scope,
                          origin="compute.firewalls.list", captured_at=CAPTURED)
    taints = dict(fact_taints)
    ledger = SourceLedger(
        sources={source.source_id: source},
        categories={"firewall_rules": CategoryScope(
            scope=scope, taint=category_taint, keys=len(table),
            source_kinds=(kind,))},
        facts={"firewall_rules": {
            key: FactOrigin(source_id=source.source_id, locator=key,
                            taint=taints.get(key, ""))
            for key in table}})
    return ReconciledSnapshot.from_snapshot(
        GcpSnapshot(captured_at=CAPTURED, firewall_rules=dict(table)),
        ledger=ledger, policy_name="api-wins")


def _ctx(snapshot, *, kind="firewall_rule", policy="", solver=None, baseline=None):
    return sec_rules.RuleContext(snapshot=snapshot, document={}, document_kind=kind,
                                 baseline=baseline, solver=solver,
                                 drift_policy=policy)


SUFFIX = "[not decided:"


# =============================================================================
# rule 1: a grounded resting on a tainted fact
# =============================================================================

def test_clean_reconciled_estate_still_grounds():
    """The floor: adjudication must not cost a clean answer."""
    v = _rule("no-open-ssh", "refute", AST_REFUTE).evaluate(_ctx(_reconciled()))
    if not HAVE_Z3:
        assert v.status == "unverified" and "z3 is not available" in v.message
        return
    assert v.status == "grounded"
    assert v.kind == "sec:vpc_firewall"
    assert SUFFIX not in v.message


def test_a_tainted_record_downgrades_the_grounded_to_unverified():
    snapshot = _reconciled(fact_taints={HTTPS: "disputed"})
    v = _rule("no-open-ssh", "refute", AST_REFUTE).evaluate(_ctx(snapshot))
    if not HAVE_Z3:
        assert v.status == "unverified" and SUFFIX not in v.message
        return
    assert v.status == "unverified"
    assert SUFFIX in v.message
    assert f"firewall_rules/{HTTPS} is tainted 'disputed'" in v.message
    # the decided answer is still carried, so a reader sees what was downgraded
    assert "the obligation holds over the document" in v.message


def test_a_different_tainted_record_still_grounds():
    """The boundary. The EGRESS rule is tainted and is not read, so the answer
    stands; a downgrade here would let one stale record silence every promise."""
    snapshot = _reconciled(fact_taints={EGRESS: "disputed"})
    v = _rule("no-open-ssh", "refute", AST_REFUTE).evaluate(_ctx(snapshot))
    if not HAVE_Z3:
        assert v.status == "unverified" and SUFFIX not in v.message
        return
    assert v.status == "grounded"
    assert SUFFIX not in v.message


# =============================================================================
# rule 2: a contradicted keeps its status under annotate, flips under abstain
# =============================================================================

def test_contradicted_keeps_its_status_under_annotate_and_flips_under_abstain():
    snapshot = _reconciled(OPEN_TABLE, fact_taints={SSH: "disputed"})
    rule = _rule("no-open-ssh", "refute", AST_REFUTE)
    annotated = rule.evaluate(_ctx(snapshot, policy="annotate"))
    abstained = rule.evaluate(_ctx(snapshot, policy="abstain"))
    if not HAVE_Z3:
        assert annotated.status == "unverified" and SUFFIX not in annotated.message
        assert abstained.status == "unverified" and SUFFIX not in abstained.message
        return
    assert annotated.status == "contradicted"
    assert SUFFIX not in annotated.message
    assert abstained.status == "unverified"
    assert drift.ABSTAIN_REASON in abstained.message


# =============================================================================
# the two gates are NOT adjudicated
# =============================================================================

def test_non_applicable_rule_is_silent_and_leaks_no_read_context():
    rule = _rule("no-open-ssh", "refute", AST_REFUTE)
    ctx = _ctx(_reconciled(fact_taints={HTTPS: "disputed"}), kind="iam_policy")
    assert rule.applies_to(ctx) is False
    assert rule.evaluate(ctx) is None
    assert reconciled.active_reads() == ()


def test_missing_input_keeps_its_own_unverified_and_is_not_rewritten():
    """A missing baseline is the rule's own abstention, not a drift one."""
    rule = _rule("pair-promise", "refute", AST_PAIR, domain="iam", state="pair")
    snapshot = _reconciled(category_taint="stale")
    v = rule.evaluate(_ctx(snapshot, kind="iam_policy"))
    assert v.status == "unverified"
    assert v.message == ("pair-promise: not evaluated — no baseline document was "
                         "given — the pair-tier rule was not evaluated")
    assert SUFFIX not in v.message


# =============================================================================
# THE UNIVERSAL-NEGATIVE PIN
# =============================================================================

def test_universal_negative_abstains_on_a_partial_view_and_grounds_on_a_complete_one():
    """Asserted AS A PAIR: the abstention is only correct if the positive case
    still works, and a gate that fires on everything has bought nothing."""
    rule = _rule("no-open-ssh", "assert_satisfiable", AST_FORALL)
    partial = rule.evaluate(_ctx(_reconciled(scope="partial", kind="tfstate")))
    complete = rule.evaluate(_ctx(_reconciled(scope="complete", kind="api")))

    assert partial.status == "unverified"
    assert partial.status != "grounded"
    assert "'firewall_rules'" in partial.message                    # the collection
    assert "snapshot category 'firewall_rules'" in partial.message  # the category
    assert "partial coverage from tfstate" in partial.message       # the reason
    assert "absence within a partial capture is not absence" in partial.message

    if not HAVE_Z3:
        assert complete.status == "unverified"
        assert "z3 is not available" in complete.message
        return
    assert complete.status == "grounded"
    assert SUFFIX not in complete.message


def test_collection_categories_maps_the_firewall_estate_collection():
    """The pin the gate rests on: the collection resolves to a real category."""
    assert provenance.COLLECTION_CATEGORIES["firewall_rules"] == "firewall_rules"
    assert sec_ast.derived_tier(AST_FORALL) == "estate"


def test_an_uncaptured_estate_still_abstains_through_the_extractor():
    """The gate did not steal the extractor's own missing_reason."""
    snapshot = ReconciledSnapshot.from_snapshot(GcpSnapshot(captured_at=CAPTURED))
    v = _rule("no-open-ssh", "assert_satisfiable", AST_FORALL).evaluate(_ctx(snapshot))
    assert v.status == "unverified"
    assert "snapshot did not capture firewall_rules" in v.message


# =============================================================================
# the sec:artifact carve-out
# =============================================================================

def test_artifact_verdict_is_emitted_unchanged_over_a_fully_tainted_estate():
    doc = sec_artifact.PromiseDoc(
        source_doc="tampered.json",
        promises=(_promise("tampered", "refute", AST_REFUTE, sexpr="(assert true)"),))
    _rules, verdicts = sec_rules.load_rules([doc])
    artifact = [v for v in verdicts if v.kind == sec_rules.ARTIFACT_KIND]
    assert len(artifact) == 1
    assert SUFFIX not in artifact[0].message
    if not HAVE_Z3:
        assert artifact[0].status == "unverified"
        assert "z3 is not available" in artifact[0].message
        return
    assert artifact[0].status == "contradicted"
    assert "the stored sexpr does not match" in artifact[0].message


def test_adjudication_skips_sec_artifact_but_not_a_domain_verdict():
    """The carve-out itself, with the identical verdict on both sides of it."""
    ctx = _ctx(_reconciled(fact_taints={HTTPS: "disputed"}))
    reads = (("firewall_rules", HTTPS),)
    message = "tampered: the stored sexpr does not match a fresh encoding"

    kept = sec_rules._adjudicate_one(
        Verdict("grounded", sec_rules.ARTIFACT_KIND, "tampered", 0, message), ctx, reads)
    assert kept.status == "grounded"
    assert kept.message == message

    graded = sec_rules._adjudicate_one(
        Verdict("grounded", "sec:vpc_firewall", "tampered", 0, message), ctx, reads)
    assert graded.status == "unverified"
    assert SUFFIX in graded.message


# =============================================================================
# degradation: no z3, and a plain snapshot
# =============================================================================

def test_no_z3_every_rule_is_unverified_and_the_adjudicator_changes_nothing():
    tainted = _reconciled(fact_taints={HTTPS: "disputed"})
    for snapshot in (_reconciled(), tainted):
        v = _rule("no-open-ssh", "refute", AST_REFUTE).evaluate(
            _ctx(snapshot, solver=BUILTIN))
        assert v.status == "unverified"
        assert "z3 is not available" in v.message
        assert SUFFIX not in v.message


def test_plain_snapshot_behaviour_is_byte_identical():
    """No ledger, no adjudication, and a captured category reads as complete —
    exactly what `sec_rules` shipped."""
    plain = GcpSnapshot(captured_at=CAPTURED, firewall_rules=dict(CLEAN_TABLE))
    v = _rule("no-open-ssh", "refute", AST_REFUTE).evaluate(_ctx(plain))
    if not HAVE_Z3:
        assert v.status == "unverified" and "z3 is not available" in v.message
    else:
        assert v.status == "grounded"
        assert v.message == ("no-open-ssh: the obligation holds over the document "
                             "— grounded")

    uncaptured = GcpSnapshot(captured_at=CAPTURED)
    absent = _rule("no-open-ssh", "refute", AST_REFUTE).evaluate(_ctx(uncaptured))
    assert absent.status == "unverified"
    assert absent.message == ("no-open-ssh: not evaluated — snapshot did not "
                              "capture firewall_rules — the estate-tier rule was "
                              "not evaluated")
