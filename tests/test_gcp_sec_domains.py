"""Tests for :mod:`gcp_grounding.sec_domains`.

HAVE_Z3-branched in the idiom of the encode/probes/rules suites: rather than
*skip* the solver-dependent cases on the builtin backend, each test asserts the
documented builtin behaviour (every rule abstains ``unverified``) when z3 is
absent and the real grounded/contradicted assertions when it is present.

The estate cases are ALSO checkout-branched. The estate snapshot tables
(``firewall_rules``, ``hierarchical_firewall_policies``) arrive with
``sx-kb-estate-tables``; :func:`estate_snapshot` builds a real
:class:`~gcp_grounding.knowledge.GcpSnapshot` when those fields exist and a
stand-in object with the same attributes when they do not, so the extractor's
``getattr``-and-compare-with-``is`` contract is exercised either way.

``estate_partial_snapshot.json`` is NOT branched: it is REQUIRED. A named
partial-estate input silently substituted by a trivially empty snapshot cannot
tell "captured everything except this table" from "captured nothing" — both
answer UNKNOWN for the same reason — so its absence is a missing dependency to
escalate, never to paper over. For the same reason the extractor count below is
the exact knowable one (see :data:`EXTRACTOR_DEPENDENCIES`) and not a floor.

The TERRAFORM PLAN ENVELOPE has its own section, because a plan is the widest
arm of the applicability table — ``applies_to`` says a plan reaches every
domain, and ``detect_kind`` labels any mapping carrying one of four top-level
keys a plan without checking its shape. Its tests replace an
``assert missing is None or ... in missing`` disjunction that accepted every
outcome the path has; each new case now pins the exact reason string, and the
plan that really does carry a firewall rule is the honest control beside them.

The last section pins the RECORD-SHAPE GUARDS: for each measured shape that
produced zero records and NO reason, the extractor now abstains naming the
record and the key, and the end-to-end verdict is ``unverified`` rather than a
``grounded`` standing on rows nobody read. Each of those tests carries its own
honest control, so an extractor that simply abstained on everything would fail
here too.

NAMED MUTATION MUST-KILLS PINNED HERE: MK-I02 through MK-I13 — the IANA protocol
table, the ragged-record sort rank, the string dimension, the all-protocols test,
the protocol-number and port bounds, the wide-range flag, and the traceback of
the extractor-failed log. Each was measured to survive this suite as it stood and
re-measured ALONE in an isolated copy before being pinned (house rule 7).
"""

import importlib.util
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from gcp_grounding import (evidence, sec_artifact, sec_ast, sec_domains,
                           sec_encode, sec_probes, sec_rules, solve)
from gcp_grounding.claims import Claim
from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.sec_ast import CollectionSpec

_SOLVER = get_solver()
Z3 = _z3_module(_SOLVER)
HAVE_Z3 = _SOLVER.backend == "z3"

_FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
_POLICIES = _FIXTURES / "policies"

CAPTURED = "2026-01-01T00:00:00Z"
SNAP = GcpSnapshot(captured_at=CAPTURED)

FW_OPEN = json.loads((_POLICIES / "fw_rule_open.json").read_text())
FW_GOOD = json.loads((_POLICIES / "fw_rule_good.json").read_text())


# -- isolation ----------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate():
    """Restore both registries and the registration guard around every test."""
    saved_collections = dict(sec_ast.COLLECTIONS)
    saved_extractors = dict(sec_rules.EXTRACTORS)
    sec_domains.reset()
    sec_domains.register()
    yield
    sec_rules.RULES.clear()
    sec_rules._LAST_WITNESS.clear()
    sec_ast.COLLECTIONS.clear()
    sec_ast.COLLECTIONS.update(saved_collections)
    sec_rules.EXTRACTORS.clear()
    sec_rules.EXTRACTORS.update(saved_extractors)
    sec_domains.reset()
    sec_domains.register()


# -- AST builders -------------------------------------------------------------

def fld(name, var="r"):
    return {"node": "field", "var": var, "field": name}


def lit(sort, value):
    return {"node": "lit", "sort": sort, "value": value}


def cmp(op, left, right):
    return {"node": "cmp", "op": op, "left": left, "right": right}


def exists(body, var="r", coll="proposed_firewall_rules"):
    return {"node": "exists", "var": var, "collection": coll, "body": body}


def forall(body, var="r", coll="proposed_firewall_rules"):
    return {"node": "forall", "var": var, "collection": coll, "body": body}


#: "no ingress firewall rule may allow tcp/22 from 0.0.0.0/0" — the bad property
#: a ``refute`` promise asserts must NOT hold. "from 0.0.0.0/0" is encoded as
#: "the source range covers the base address of the whole internet", which only
#: an internet-wide range does.
OPEN_SSH = exists({"node": "and", "args": [
    cmp("eq", fld("direction"), lit("Str", "INGRESS")),
    cmp("eq", fld("action"), lit("Str", "allow")),
    cmp("eq", fld("disabled"), lit("Bool", False)),
    cmp("eq", fld("protocol"), lit("Proto", 6)),
    {"node": "port_in", "term": fld("port"), "lo": 22, "hi": 22},
    {"node": "cidr_contains", "cidr": fld("source_range"),
     "addr": lit("Ip4", "0.0.0.0")},
]})


# -- promise / context builders ----------------------------------------------

def _source():
    return sec_artifact.Source(file="firewall.md", line=3,
                               text="no ingress firewall rule may allow tcp/22 "
                                    "from 0.0.0.0/0")


def promise(pid, mode, ast, *, domain="vpc_firewall", state="proposal"):
    """A compiled Promise: real sexpr and minted witnesses under z3, structurally
    valid placeholders without it (``evaluate`` reads neither)."""
    if HAVE_Z3:
        formula, consts = sec_encode.symbolic(Z3, ast)
        obl = sec_probes.obligation(Z3, formula, mode)
        positive, negative = sec_probes.mint(Z3, obl, consts)
        assert positive is not None and negative is not None, "witnesses must mint"
        sexpr = formula.sexpr()
    else:
        sexpr = "(assert true)"
        positive = negative = {"placeholder": "x"}
    return sec_artifact.Promise(
        id=pid, source=_source(), domain=domain, mode=mode, state=state,
        severity="high", vocabulary=(), ast=ast, sexpr=sexpr,
        free_consts=tuple(sec_ast.free_consts(ast)),
        positive=sec_artifact.Witness(assignment=positive, origin="z3-model"),
        negative=sec_artifact.Witness(assignment=negative, origin="z3-model"),
        wellformedness=sec_artifact.Wellformedness(satisfiable=True,
                                                   non_tautological=True),
        status="compiled", reason="")


def ctx(document=None, kind=None, *, snapshot=SNAP, baseline=None):
    return sec_rules.RuleContext(snapshot=snapshot, document=document,
                                 document_kind=kind, baseline=baseline)


def estate_snapshot(**tables):
    """A snapshot carrying estate record tables, in either checkout.

    ``GcpSnapshot`` grows the record-table fields with ``sx-kb-estate-tables``;
    until then a stand-in with the same attributes exercises the same
    ``getattr``/``is`` path in the extractor."""
    try:
        return GcpSnapshot(captured_at=CAPTURED, **tables)
    except TypeError:
        return SimpleNamespace(captured_at=CAPTURED, **tables)


def extract(collection, context):
    return sec_rules.EXTRACTORS[collection](context)


#: collection -> the domain claims module its extractor needs, or ``None`` when
#: :func:`sec_domains.register` installs it unconditionally. This is what makes
#: the extractor count EXACTLY KNOWABLE in any checkout: a floor (``>= 2``) would
#: have passed just as happily if a domain silently stopped registering.
EXTRACTOR_DEPENDENCIES = {
    "proposed_role_permissions": None,
    "proposed_firewall_rules": "fw_claims",
    "firewall_rules": None,
    "armor_rules": "armor_claims",
    "hier_firewall_rules": None,
    "perimeter_resources": "vpcsc_claims",
    "perimeter_restricted_services": "vpcsc_claims",
}


def expected_extractors():
    """The collections ``register`` must install an extractor for in THIS
    checkout, resolved from disk rather than from ``sec_domains``' own state."""
    return {collection for collection, module in EXTRACTOR_DEPENDENCIES.items()
            if module is None
            or importlib.util.find_spec(f"gcp_grounding.{module}") is not None}


# =============================================================================
# registration
# =============================================================================

def test_register_is_idempotent(monkeypatch):
    """The second call registers nothing — asserted by a counter."""
    sec_domains.reset()
    # The base-collection overrides land only over the shipped built-ins
    # (a prior registration outranks a side-effect import), so put the
    # built-ins back: the fixture's own register() left the wrappers in
    # place, and counting a skipped override would read as a lost one.
    for name in sec_domains.BASE_COLLECTION_OVERRIDES:
        sec_rules.EXTRACTORS[name] = getattr(sec_rules, name)
    calls = {"collections": 0, "extractors": 0}
    real_collection = sec_ast.register_collection
    real_extractor = sec_rules.register_extractor

    def count_collection(spec):
        calls["collections"] += 1
        return real_collection(spec)

    def count_extractor(name, fn):
        calls["extractors"] += 1
        return real_extractor(name, fn)

    monkeypatch.setattr(sec_ast, "register_collection", count_collection)
    monkeypatch.setattr(sec_rules, "register_extractor", count_extractor)

    sec_domains.register()
    first = dict(calls)
    assert first["collections"] == len(sec_domains.COLLECTION_SPECS)
    # the EXACT knowable count, not a floor: every collection whose claims
    # module this checkout carries, plus the two that always register, plus the
    # two base-collection overrides (unconditional — everything their terraform
    # arm needs is a hard import of sec_domains itself)
    assert first["extractors"] == (len(expected_extractors())
                                   + len(sec_domains.BASE_COLLECTION_OVERRIDES))
    assert {name for name in EXTRACTOR_DEPENDENCIES
            if name in sec_rules.EXTRACTORS} == expected_extractors()
    for name in sec_domains.BASE_COLLECTION_OVERRIDES:
        assert name in sec_rules.EXTRACTORS, name
    assert sec_domains.registered() is True

    sec_domains.register()
    assert calls == first


def test_registering_an_identical_spec_again_does_not_raise():
    """The collections are already registered; re-running must be a no-op, not a
    ValueError — a double import of a domain module cannot break a run."""
    sec_domains.reset()
    sec_domains.register()
    sec_domains.reset()
    sec_domains.register()
    for spec in sec_domains.COLLECTION_SPECS:
        assert sec_ast.COLLECTIONS[spec.name] == spec


def test_collections_registered_with_the_documented_tiers():
    tiers = {name: sec_ast.COLLECTIONS[name].tier for name in (
        "proposed_firewall_rules", "firewall_rules", "hier_firewall_rules",
        "armor_rules", "perimeter_resources", "perimeter_restricted_services")}
    assert tiers == {
        "proposed_firewall_rules": "proposal",
        "firewall_rules": "estate",
        "hier_firewall_rules": "estate",
        "armor_rules": "proposal",
        "perimeter_resources": "proposal",
        "perimeter_restricted_services": "proposal",
    }
    # every Cidr field declares its Ip4 companion, which is what lets the
    # existing cidr_contains encoder apply with no override
    for spec in sec_domains.COLLECTION_SPECS:
        for field, sort in spec.fields.items():
            if sort == "Cidr":
                assert spec.fields.get(f"{field}_mask") == "Ip4"


def test_domain_names_are_sec_artifact_domains_compatible():
    """The domains register in ``sec_artifact.DOMAINS`` order — no edit to
    ``sec_artifact`` is needed, since DOMAINS already lists all six."""
    ordered = [d for d in sec_artifact.DOMAINS if d in sec_domains.DOMAIN_COLLECTIONS]
    assert list(sec_domains.DOMAIN_COLLECTIONS) == ordered
    flattened = [name for names in sec_domains.DOMAIN_COLLECTIONS.values()
                 for name in names]
    assert [spec.name for spec in sec_domains.COLLECTION_SPECS] == flattened


def test_every_registered_collection_has_a_known_extractor_dependency():
    """The table the exact extractor count is computed from covers every spec —
    a new collection outside it would make that count knowable by accident."""
    assert set(EXTRACTOR_DEPENDENCIES) == {spec.name
                                           for spec in sec_domains.COLLECTION_SPECS}
    for module in set(EXTRACTOR_DEPENDENCIES.values()) - {None}:
        assert module in sec_domains.DOMAIN_MODULES.values(), module
    # The base-collection overrides are sec_ast's own four-field collections,
    # not specs this module registers, so they stay OUT of both tables above —
    # their registration is counted separately in test_register_is_idempotent.
    assert not set(sec_domains.BASE_COLLECTION_OVERRIDES) & set(EXTRACTOR_DEPENDENCIES)
    for name in sec_domains.BASE_COLLECTION_OVERRIDES:
        assert name in sec_ast.COLLECTIONS, name


def test_absent_domain_module_still_registers_the_others(monkeypatch):
    """A forced ImportError skips just that domain and never raises."""
    monkeypatch.delitem(__import__("sys").modules, "gcp_grounding.fw_claims",
                        raising=False)
    real = sec_domains.importlib.import_module

    def failing(name, *args, **kwargs):
        if name == "gcp_grounding.fw_claims":
            raise ImportError("simulated partial checkout")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(sec_domains.importlib, "import_module", failing)
    sec_rules.EXTRACTORS.pop("proposed_firewall_rules", None)
    sec_domains.reset()
    sec_domains.register()  # must not raise

    assert "proposed_firewall_rules" not in sec_rules.EXTRACTORS
    assert "firewall_rules" in sec_rules.EXTRACTORS
    assert "hier_firewall_rules" in sec_rules.EXTRACTORS
    # the collection is still registered, so a promise naming it compiles and
    # abstains loudly instead of failing as an unknown collection
    assert "proposed_firewall_rules" in sec_ast.COLLECTIONS


# =============================================================================
# the AST surface the domains unlock
# =============================================================================

def test_derived_tier_of_an_estate_collection_is_estate():
    ast = forall({"node": "true"}, var="f", coll="firewall_rules")
    assert sec_ast.derived_tier(ast) == "estate"
    assert sec_ast.derived_tier(forall({"node": "true"})) == "proposal"


def test_cidr_contains_validates_because_the_mask_companion_is_declared():
    ast = exists({"node": "cidr_contains", "cidr": fld("source_range"),
                  "addr": lit("Ip4", "0.0.0.0")})
    sec_ast.validate(ast)  # must not raise

    # the control: the same shape over a collection whose Cidr field has no
    # companion is exactly what sec_ast rejects
    sec_ast.register_collection(
        CollectionSpec("sec_domains_no_mask", "proposal", {"range": "Cidr"}))
    bad = exists({"node": "cidr_contains", "cidr": fld("range", "x"),
                  "addr": lit("Ip4", "0.0.0.0")},
                 var="x", coll="sec_domains_no_mask")
    with pytest.raises(sec_ast.InvalidAst):
        sec_ast.validate(bad)


def test_port_in_validates_and_encodes():
    ast = exists({"node": "port_in", "term": fld("port"), "lo": 22, "hi": 22})
    sec_ast.validate(ast)
    if not HAVE_Z3:
        with pytest.raises(sec_encode.UnsupportedTerm):
            sec_encode.ground(Z3, ast, {"proposed_firewall_rules": []})
        return
    instance = {"proposed_firewall_rules": [{"port": 22}]}
    assert solve.decide(Z3, sec_encode.ground(Z3, ast, instance)) is True
    instance = {"proposed_firewall_rules": [{"port": 443}]}
    assert solve.decide(Z3, sec_encode.ground(Z3, ast, instance)) is False


# =============================================================================
# end-to-end: a domain promise that actually runs
# =============================================================================

def test_refute_promise_contradicted_on_open_and_grounded_on_good():
    """The proof that a firewall promise is executable and not inert."""
    rule = sec_rules.CompiledRule(promise=promise("no-open-ssh", "refute", OPEN_SSH))
    good = rule.evaluate(ctx(FW_GOOD, "firewall_rule"))
    opened = rule.evaluate(ctx(FW_OPEN, "firewall_rule"))
    if not HAVE_Z3:
        assert opened.status == "unverified" and good.status == "unverified"
        return
    assert opened.status == "contradicted" and opened.kind == "sec:vpc_firewall"
    assert "fw-allow-open" in opened.message
    assert good.status == "grounded"
    witness = sec_rules.last_witness("no-open-ssh")
    assert witness["collection"] == "proposed_firewall_rules"
    assert witness["record"]["port"] == 22


def test_polarity_mirror_flips_the_buckets():
    """The same AST under assert_satisfiable yields the opposite verdict."""
    if not HAVE_Z3:
        return
    refute = sec_rules.CompiledRule(promise=promise("mirror-ref", "refute", OPEN_SSH))
    asserted = sec_rules.CompiledRule(
        promise=promise("mirror-asr", "assert_satisfiable", OPEN_SSH))
    assert refute.evaluate(ctx(FW_OPEN, "firewall_rule")).status == "contradicted"
    assert asserted.evaluate(ctx(FW_OPEN, "firewall_rule")).status == "grounded"


def test_a_promise_over_a_non_firewall_document_is_silent_not_wrong():
    rule = sec_rules.CompiledRule(promise=promise("no-open-ssh2", "refute", OPEN_SSH))
    assert rule.evaluate(ctx({"bindings": []}, "iam_policy")) is None


# =============================================================================
# flattening
# =============================================================================

def two_by_two():
    return {
        "kind": "compute#firewall",
        "name": "fw-two-by-two",
        "network": "projects/acme-prod/global/networks/vpc-main",
        "direction": "INGRESS",
        "sourceRanges": ["10.0.0.0/8", "192.168.0.0/16"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22", "443"]}],
    }


def test_two_ranges_and_two_ports_flatten_to_four_records():
    records, missing = extract("proposed_firewall_rules",
                               ctx(two_by_two(), "firewall_rule"))
    assert missing is None
    assert len(records) == 4
    assert {(r["source_range"], r["port"]) for r in records} == {
        ("10.0.0.0/8", 22), ("10.0.0.0/8", 443),
        ("192.168.0.0/16", 22), ("192.168.0.0/16", 443)}
    # every row carries the rule's scalars, its Ip4 mask companion and the
    # protocol number, and the ordering is deterministic
    assert all(r["name"] == "fw-two-by-two" and r["protocol"] == 6 for r in records)
    assert {r["source_range_mask"] for r in records} == {"255.0.0.0", "255.255.0.0"}
    again, _ = extract("proposed_firewall_rules", ctx(two_by_two(), "firewall_rule"))
    assert again == records


def test_all_ports_omits_the_port_key_rather_than_dropping_the_rule():
    """An all-ports rule still produces a row (so a port-free promise judges it),
    but a port-mentioning promise abstains loudly instead of under-matching."""
    doc = dict(two_by_two(), allowed=[{"IPProtocol": "tcp"}])
    records, missing = extract("proposed_firewall_rules", ctx(doc, "firewall_rule"))
    assert missing is None
    assert len(records) == 2 and all("port" not in r for r in records)
    if not HAVE_Z3:
        return
    with pytest.raises(sec_encode.UnsupportedTerm):
        sec_encode.ground(Z3, OPEN_SSH, {"proposed_firewall_rules": list(records)})


def test_unsupported_payload_yields_a_missing_reason_and_no_records():
    """A vacuous ``forall`` pass must be impossible: the rule is named, not
    dropped."""
    broken = {"kind": "compute#firewall", "name": "fw-broken",
              "direction": "INGRESS",
              "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}
    records, missing = extract("proposed_firewall_rules", ctx(broken, "firewall_rule"))
    assert records == ()
    assert "fw-broken" in missing and "network" in missing

    rule = sec_rules.CompiledRule(
        promise=promise("no-open-ssh3", "refute", OPEN_SSH))
    verdict = rule.evaluate(ctx(broken, "firewall_rule"))
    assert verdict.status == "unverified" and "fw-broken" in verdict.message


def test_an_unparseable_port_or_protocol_abstains_by_name():
    doc = dict(two_by_two(), allowed=[{"IPProtocol": "tcp", "ports": ["http"]}])
    records, missing = extract("proposed_firewall_rules", ctx(doc, "firewall_rule"))
    assert records == () and "fw-two-by-two" in missing and "http" in missing

    doc = dict(two_by_two(), allowed=[{"IPProtocol": "quic", "ports": ["443"]}])
    records, missing = extract("proposed_firewall_rules", ctx(doc, "firewall_rule"))
    assert records == () and "quic" in missing


def test_a_non_firewall_document_reports_the_missing_input():
    records, missing = extract("proposed_firewall_rules", ctx({"bindings": []},
                                                              "iam_policy"))
    assert records == () and "not a VPC firewall rule" in missing
    records, missing = extract("proposed_firewall_rules", ctx(None, None))
    assert records == () and "no document under review" in missing


# -----------------------------------------------------------------------------
# the terraform plan envelope — the widest arm of the applicability table
# -----------------------------------------------------------------------------
#
# ``CompiledRule.applies_to`` returns True for a plan in EVERY domain, and
# ``preflight.detect_kind`` calls any mapping carrying one of four top-level keys
# a plan without looking at its shape. The plan walker returns an empty claim
# list for a mapping it cannot walk, with no reason — so an unvalidated envelope
# is the one input that can ground every domain at once over zero records.

#: The empty document. ``detect_kind`` would not label it, but nothing stops a
#: caller passing ``document_kind="tf_plan"`` — the gate's own kind argument is
#: how a plan reaches these extractors.
EMPTY_PLAN: dict = {}

#: MEASURED: ``resource_changes`` a string and ``planned_values`` an integer.
#: ``detect_kind`` says "tf_plan" on the strength of the top-level keys alone.
GARBAGE_PLAN = {"format_version": "1.2", "planned_values": 3,
                "resource_changes": "google_compute_firewall.web"}

#: A plan that IS understood — a well-formed ``resource_changes`` list — and
#: simply carries no firewall rule. "The plan was understood and mentions no
#: firewall rule" is a different fact from "every firewall rule in the plan
#: complies", and only the second one is a pass.
NO_FIREWALL_PLAN = {
    "format_version": "1.2",
    "resource_changes": [{
        "address": "google_storage_bucket.assets", "mode": "managed",
        "type": "google_storage_bucket",
        "provider_name": "registry.terraform.io/hashicorp/google",
        "change": {"actions": ["create"], "after": {"name": "acme-assets"}},
    }],
}


def plan_rule(pid):
    """A ``forall`` over the proposal-tier firewall rules — the shape that reads
    an empty instance as a trivially true formula and grounds on it."""
    return sec_rules.CompiledRule(promise=promise(
        pid, "assert_satisfiable",
        forall(cmp("eq", fld("action"), lit("Str", "deny")))))


def test_a_terraform_plan_reaches_the_firewall_claims_through_the_registry():
    """THE HONEST CONTROL for the three abstentions below: a plan that really
    does carry a ``google_compute_firewall`` still yields rows and NO reason.

    Replaces an ``assert missing is None or ... in missing`` disjunction that
    could not fail: it accepted both a plan that grounded and a plan that
    abstained, which is every outcome this path has."""
    plan = json.loads((_POLICIES / "fw_tf_plan.json").read_text())
    records, missing = extract("proposed_firewall_rules", ctx(plan, "tf_plan"))
    assert missing is None
    assert [r["name"] for r in records] == ["fw-allow-web"]
    assert records[0]["port"] == 443 and records[0]["source_range"] == "10.0.0.0/8"


def test_the_empty_document_typed_as_a_plan_abstains_naming_both_sections():
    records, missing = extract("proposed_firewall_rules", ctx(EMPTY_PLAN, "tf_plan"))
    assert records == ()
    assert missing == (
        "the terraform plan under review has neither a readable 'planned_values' "
        "mapping nor a readable 'resource_changes' list (has no 'planned_values' "
        "key, so its value was never captured; has no 'resource_changes' key, so "
        "its records were never captured) — the rule was not evaluated")

    verdict = plan_rule("plan-empty").evaluate(ctx(EMPTY_PLAN, "tf_plan"))
    assert verdict.status == "unverified"
    assert "terraform plan under review" in verdict.message
    assert "'planned_values'" in verdict.message
    assert "'resource_changes'" in verdict.message


def test_a_garbage_shaped_plan_abstains_naming_the_malformed_keys():
    records, missing = extract("proposed_firewall_rules",
                               ctx(GARBAGE_PLAN, "tf_plan"))
    assert records == ()
    assert missing == (
        "the terraform plan under review has neither a readable 'planned_values' "
        "mapping nor a readable 'resource_changes' list (has a 'planned_values' "
        "that is not a Mapping, got int; has no readable 'resource_changes' list, "
        "got str) — the rule was not evaluated")

    verdict = plan_rule("plan-garbage").evaluate(ctx(GARBAGE_PLAN, "tf_plan"))
    assert verdict.status == "unverified"
    assert "terraform plan under review" in verdict.message
    assert "'planned_values' that is not a Mapping, got int" in verdict.message
    assert "no readable 'resource_changes' list, got str" in verdict.message


def test_a_readable_plan_with_no_firewall_resource_is_unverified_not_grounded():
    """The envelope is READABLE here and the walker understood it — it simply
    found a storage bucket. That is not a firewall rule that complies."""
    records, missing = extract("proposed_firewall_rules",
                               ctx(NO_FIREWALL_PLAN, "tf_plan"))
    assert records == ()
    assert missing == ("the terraform plan under review carries no VPC firewall "
                       "rule resources — the rule was not evaluated over any "
                       "record")

    verdict = plan_rule("plan-no-firewall").evaluate(ctx(NO_FIREWALL_PLAN,
                                                         "tf_plan"))
    assert verdict.status == "unverified"
    assert "terraform plan under review" in verdict.message
    assert "carries no VPC firewall rule resources" in verdict.message


def test_the_plan_envelope_is_read_through_the_evidence_ledger():
    """The distinction reaches the LEDGER as well as the message: a present and
    empty ``resource_changes`` is a POSITIVE observation of emptiness, recorded
    as one, while the unreadable envelopes above are counted as a collection
    somebody tried to read and never as an observation."""
    plan = {"planned_values": {"root_module": {}}, "resource_changes": []}
    with evidence.ledger() as observed:
        records, missing = extract("proposed_firewall_rules", ctx(plan, "tf_plan"))
    assert records == () and "carries no VPC firewall rule resources" in missing
    assert observed.collections_read == 1 and observed.rows_examined == 0
    assert observed.empty_observed == (
        "the terraform plan under review: 'resource_changes' is present and "
        "holds no records",)

    with evidence.ledger() as unreadable:
        extract("proposed_firewall_rules", ctx(GARBAGE_PLAN, "tf_plan"))
    assert unreadable.collections_read == 1
    assert unreadable.empty_observed == ()


# =============================================================================
# the sec_rules base collections' terraform arm (iam_bindings / org_policy_rules)
# =============================================================================
#
# ``register`` overrides the two base collections' EXTRACTORS entries with a
# dispatch: a ``tf_plan`` document takes the claim-built arm, every other kind
# reaches sec_rules' untouched built-in — byte-identical REST behaviour, only
# terraform documents gain evaluation. The REST-mismatch carve-out (an
# org-policy promise over a plain IAM policy document) is re-pinned HERE, at the
# registered-extractor level, beside the terraform cases that must differ.


def iam_plan(*bindings, rtype="google_project_iam_binding", extra=()):
    """A plan whose root module holds one *rtype* resource per (name, values)."""
    resources = [{"address": f"{rtype}.{name}", "mode": "managed", "type": rtype,
                  "name": name,
                  "provider_name": "registry.terraform.io/hashicorp/google",
                  "values": values} for name, values in bindings]
    resources.extend(extra)
    return {"format_version": "1.2",
            "planned_values": {"root_module": {"resources": resources}}}


ORG_TF_VALUES = {
    "name": "projects/p/policies/iam.disableServiceAccountKeyCreation",
    "parent": "projects/p",
    "spec": [{"rules": [{"enforce": "TRUE"}]}],
}

OWNER_TO_OUTSIDER = {"role": "roles/owner", "project": "p",
                     "members": ["user:mallory@outsider.example"]}

#: "no binding may grant roles/owner" — the iam analog of OPEN_SSH.
OWNER_GRANTED = exists(cmp("eq", fld("role", var="b"), lit("Str", "roles/owner")),
                       var="b", coll="iam_bindings")

#: "some rule for the constraint sets enforce false" — refute-mode reads its
#: absence as the promise holding.
SA_KEYS_UNENFORCED = exists({"node": "and", "args": [
    cmp("eq", fld("constraint", var="r"),
        lit("Str", "iam.disableServiceAccountKeyCreation")),
    cmp("eq", fld("enforce", var="r"), lit("Bool", False)),
]}, var="r", coll="org_policy_rules")


def test_the_base_overrides_delegate_every_rest_kind_to_the_untouched_builtin():
    """REST behaviour is byte-identical: the registered extractor and the raw
    sec_rules built-in return the SAME pair for an IAM document, and the
    REST-mismatch carve-out still answers not-evaluated — an org-policy promise
    handed a plain IAM policy document abstains exactly as it always did."""
    iam_doc = {"bindings": [{"role": "roles/owner",
                             "members": ["user:eve@acme.example"]}]}
    registered = extract("iam_bindings", ctx(iam_doc, "iam_policy"))
    assert registered == sec_rules.iam_bindings(ctx(iam_doc, "iam_policy"))
    assert registered[1] is None and registered[0]

    # the carve-out, at the registered level: a plain IAM policy document is
    # not an Org Policy, and only TERRAFORM documents gained evaluation
    records, missing = extract("org_policy_rules", ctx(iam_doc, "iam_policy"))
    assert records == ()
    assert missing == "the document under review is not an Org Policy"
    records, missing = extract("iam_bindings", ctx({"spec": {"rules": []}},
                                                   "org_policy"))
    assert records == ()
    assert missing == "the document under review is not an IAM allow policy"


def test_register_never_stomps_an_extractor_someone_installed_first():
    """The MK-I16 landmine, pinned: register() runs as a lazy side effect of
    the first evaluate(), so a test- or operator-installed extractor must
    survive it — clobbering the caller's registration from inside their own
    call flipped the mutation contract's witness on isolated runs. The
    override may land only over the shipped built-in."""
    def mine(context):
        return (), "mine"
    for name in sec_domains.BASE_COLLECTION_OVERRIDES:
        sec_rules.EXTRACTORS[name] = mine
        sec_domains.reset()
        sec_domains.register()
        assert sec_rules.EXTRACTORS[name] is mine, name
        # And the built-in still gains the terraform arm when it is in place.
        sec_rules.EXTRACTORS[name] = getattr(sec_rules, name)
        sec_domains.reset()
        sec_domains.register()
        assert sec_rules.EXTRACTORS[name] is not getattr(sec_rules, name), name


def test_a_terraform_plan_reaches_the_iam_claims_through_the_tf_arm():
    """THE HONEST CONTROL: a plan that really carries bindings yields rows built
    from the claims — REST-shaped role/member, the block address threaded under
    WITNESS_ADDRESS_FIELD, sorted by (role, member) like the REST extractor."""
    plan = iam_plan(
        ("viewer", {"role": "roles/viewer", "project": "p",
                    "members": ["group:eng@acme.example"]}),
        ("contractor_owner", OWNER_TO_OUTSIDER))
    records, missing = extract("iam_bindings", ctx(plan, "tf_plan"))
    assert missing is None
    assert [r["role"] for r in records] == ["roles/owner", "roles/viewer"]
    assert records[0]["member"] == "user:mallory@outsider.example"
    assert records[0][sec_rules.WITNESS_ADDRESS_FIELD] == \
        "google_project_iam_binding.contractor_owner"
    # no cel claim pinned a condition, so the keys are OMITTED — not spelled
    # False, which could fabricate a refutation of a condition-mentioning
    # promise over a request-time condition the claims conservatively skip
    assert all("condition" not in r and "has_condition" not in r
               for r in records)

    rule = sec_rules.CompiledRule(
        promise=promise("no-owner-tf", "refute", OWNER_GRANTED, domain="iam"))
    verdict = rule.evaluate(ctx(plan, "tf_plan"))
    if not HAVE_Z3:
        assert verdict.status == "unverified" and "z3" in verdict.message
        return
    assert verdict.status == "contradicted"
    assert "(google_project_iam_binding.contractor_owner)" in verdict.message
    assert "member='user:mallory@outsider.example'" in verdict.message
    assert "role='roles/owner'" in verdict.message


def test_an_offline_decidable_condition_rides_along_when_its_claim_exists():
    values = dict(OWNER_TO_OUTSIDER,
                  condition=[{"title": "t",
                              "expression": 'request.time < timestamp("2027-01-01T00:00:00Z")'}])
    records, missing = extract("iam_bindings",
                               ctx(iam_plan(("timed", values)), "tf_plan"))
    assert missing is None
    assert records[0]["has_condition"] is True
    assert records[0]["condition"].startswith("request.time <")


def test_a_counted_binding_yields_no_row_and_abstains_naming_the_block():
    """A literal ``count`` (a ``.tf.json`` keeps it as a plain attribute) means
    the block may expand zero times — a row could fabricate a refutation."""
    for meta in ("count", "for_each"):
        plan = iam_plan(("counted", dict(OWNER_TO_OUTSIDER, **{meta: 0})))
        records, missing = extract("iam_bindings", ctx(plan, "tf_plan"))
        assert records == (), meta
        assert f"'{meta}'" in missing and "counted" in missing, missing
        assert "no row was minted" in missing


def test_a_binding_with_members_but_no_role_abstains_instead_of_guessing():
    plan = iam_plan(("mystery", {"project": "p", "role": 7,
                                 "members": ["user:eve@acme.example"]}))
    records, missing = extract("iam_bindings", ctx(plan, "tf_plan"))
    assert records == ()
    assert "mystery" in missing and "no role claim" in missing


def test_a_members_value_that_is_not_a_list_abstains_beside_a_healthy_sibling():
    """The adversarial-review probe, pinned: ``members: "user:x"`` (a bare
    string — the classic typo) yields no member claims, and before the guard
    the binding vanished whenever any sibling supplied rows — a forall promise
    passed over a grant nobody read."""
    plan = iam_plan(("healthy", dict(OWNER_TO_OUTSIDER)),
                    ("typo", {"role": "roles/owner", "project": "p",
                              "members": "user:mallory@outsider.example"}))
    records, missing = extract("iam_bindings", ctx(plan, "tf_plan"))
    assert records == ()
    assert "typo" in missing and "no member claims" in missing


def test_non_string_member_entries_abstain_instead_of_coercing_a_spelling():
    """``members: [null]`` used to reach the rows as the str() coercion
    ``member='None'`` and refute the domain promise — a fabricated spelling.
    The REST extractor refuses these shapes; the tf arm now matches it."""
    plan = iam_plan(("coerced", {"role": "roles/owner", "project": "p",
                                 "members": [None]}))
    records, missing = extract("iam_bindings", ctx(plan, "tf_plan"))
    assert records == ()
    assert "coerced" in missing and "non-string member" in missing


def test_a_binding_that_yielded_no_claims_at_all_abstains_by_census():
    """Role stripped AND members malformed leaves zero claims, so the
    claims-side grouping never sees the block; the plan-side census must."""
    plan = iam_plan(("healthy", dict(OWNER_TO_OUTSIDER)),
                    ("ghost", {"project": "p", "members": "user:x"}))
    records, missing = extract("iam_bindings", ctx(plan, "tf_plan"))
    assert records == ()
    assert "ghost" in missing and "no readable claims" in missing


def test_an_org_policy_whose_name_yields_no_constraint_abstains_by_census():
    """The org-side probe, pinned: a garbled policy name emits no constraint
    claim, and before the census the policy was invisible next to a healthy
    sibling — its enforce FALSE never read, the promise still holding."""
    garbled = {"name": "not-a-policy-name", "parent": "projects/p",
               "spec": [{"rules": [{"enforce": "FALSE"}]}]}
    plan = iam_plan(("no_sa_keys", ORG_TF_VALUES), ("garbled", garbled),
                    rtype="google_org_policy_policy")
    records, missing = extract("org_policy_rules", ctx(plan, "tf_plan"))
    assert records == ()
    assert "garbled" in missing and "no constraint claim" in missing


def test_a_plan_with_no_binding_resources_abstains_not_grounds():
    records, missing = extract("iam_bindings", ctx(NO_FIREWALL_PLAN, "tf_plan"))
    assert records == ()
    assert missing == ("the terraform plan under review carries no IAM binding "
                       "resources — the rule was not evaluated over any record")
    records, missing = extract("org_policy_rules",
                               ctx(NO_FIREWALL_PLAN, "tf_plan"))
    assert records == ()
    assert missing == ("the terraform plan under review carries no Org Policy "
                       "resources — the rule was not evaluated over any record")


def test_the_tf_arm_validates_the_plan_envelope_like_the_firewall_arm():
    records, missing = extract("iam_bindings", ctx(GARBAGE_PLAN, "tf_plan"))
    assert records == ()
    assert "'planned_values' that is not a Mapping, got int" in missing
    assert "no readable 'resource_changes' list, got str" in missing


def test_org_policy_rows_from_a_terraform_plan_carry_the_fetched_enforce():
    """The claims attest WHICH key the rule sets; the boolean itself is fetched
    at the claim's own anchor — and the row is REST-shaped, constraint prefix
    stripped, with the block address riding along."""
    plan = iam_plan(("no_sa_keys", ORG_TF_VALUES), rtype="google_org_policy_policy")
    records, missing = extract("org_policy_rules", ctx(plan, "tf_plan"))
    assert missing is None
    assert records == ({"constraint": "iam.disableServiceAccountKeyCreation",
                        "is_list": False, "enforce": True, "value": "",
                        sec_rules.WITNESS_ADDRESS_FIELD:
                            "google_org_policy_policy.no_sa_keys"},)

    rule = sec_rules.CompiledRule(promise=promise(
        "sa-keys-tf", "refute", SA_KEYS_UNENFORCED, domain="org_policy"))
    verdict = rule.evaluate(ctx(plan, "tf_plan"))
    if not HAVE_Z3:
        assert verdict.status == "unverified" and "z3" in verdict.message
        return
    assert verdict.status == "grounded"
    assert "holds over the document" in verdict.message


def test_a_list_typed_org_rule_yields_one_row_per_value_with_rest_semantics():
    values = {"name": "projects/p/policies/gcp.resourceLocations",
              "spec": [{"rules": [{"values": [{"allowed_values":
                                               ["in:us-locations",
                                                "in:eu-locations"]}]}]}]}
    plan = iam_plan(("locations", values), rtype="google_org_policy_policy")
    records, missing = extract("org_policy_rules", ctx(plan, "tf_plan"))
    assert missing is None
    assert [r["value"] for r in records] == ["in:eu-locations", "in:us-locations"]
    # the REST extractor's own reading of a rule that does not state enforce
    assert all(r["is_list"] is True and r["enforce"] is False for r in records)


def test_an_allow_all_org_rule_is_a_shape_the_conservative_extraction_refuses():
    values = {"name": "projects/p/policies/gcp.resourceLocations",
              "spec": [{"rules": [{"allow_all": "TRUE"}]}]}
    plan = iam_plan(("open", values), rtype="google_org_policy_policy")
    records, missing = extract("org_policy_rules", ctx(plan, "tf_plan"))
    assert records == ()
    assert "'allow_all'" in missing and "does not evaluate" in missing


def test_an_org_policy_whose_rules_yield_no_claim_abstains_by_address():
    """tf_claims skips an ambiguous rule (two value-type keys at once) silently;
    dropping the policy would let a forall pass over rules nobody read."""
    values = {"name": "projects/p/policies/iam.disableServiceAccountKeyCreation",
              "spec": [{"rules": [{"enforce": "TRUE",
                                   "deny_all": "TRUE"}]}]}
    plan = iam_plan(("ambiguous", values), rtype="google_org_policy_policy")
    records, missing = extract("org_policy_rules", ctx(plan, "tf_plan"))
    assert records == ()
    assert "google_org_policy_policy.ambiguous" in missing
    assert "yielded no rule claim" in missing


# =============================================================================
# estate tiers
# =============================================================================

ESTATE_FIREWALL = {
    "projects/acme-prod/global/firewalls/allow-iap-ssh": {
        "network": "projects/acme-prod/global/networks/vpc-main",
        "direction": "INGRESS", "action": "allow", "priority": 800,
        "disabled": False, "source_ranges": ["35.235.240.0/20"],
        "destination_ranges": [], "source_tags": [], "target_tags": [],
        "layer4": [{"protocol": "tcp", "ports": ["22"]}],
    },
}

ESTATE_HIER = {
    "organizations/1/locations/global/firewallPolicies/fp-baseline": {
        "attachments": ["organizations/1"],
        "rules": [{
            "action": "deny", "direction": "INGRESS", "disabled": False,
            "priority": 100,
            "match": {"src_ip_ranges": ["0.0.0.0/0"], "dest_ip_ranges": [],
                      "layer4": [{"protocol": "tcp", "ports": ["3389"]}]},
        }],
    },
}


def test_estate_firewall_rules_flatten_from_the_snapshot_table():
    snapshot = estate_snapshot(firewall_rules=ESTATE_FIREWALL)
    records, missing = extract("firewall_rules", ctx(snapshot=snapshot))
    assert missing is None
    assert len(records) == 1
    record = records[0]
    assert record["name"].endswith("allow-iap-ssh")
    assert record["source_range"] == "35.235.240.0/20"
    assert record["source_range_mask"] == "255.255.240.0"
    assert record["protocol"] == 6 and record["port"] == 22
    assert record["priority"] == 800 and record["disabled"] is False


def test_estate_hier_firewall_rules_flatten_per_attachment():
    snapshot = estate_snapshot(hierarchical_firewall_policies=ESTATE_HIER)
    records, missing = extract("hier_firewall_rules", ctx(snapshot=snapshot))
    assert missing is None
    assert len(records) == 1
    record = records[0]
    assert record["policy"].endswith("fp-baseline")
    assert record["node"] == "organizations/1"
    assert record["src_range"] == "0.0.0.0/0" and record["src_range_mask"] == "0.0.0.0"
    assert record["action"] == "deny" and record["priority"] == 100
    assert record["protocol"] == 6 and record["port"] == 3389


def test_an_uncaptured_estate_collection_reports_the_uncaptured_reason():
    """``estate_partial_snapshot.json`` captures the vocabularies but no record
    table — and it is REQUIRED, never substituted.

    A trivially empty snapshot standing in for the named partial-estate input
    cannot tell "captured everything except this table" from "captured nothing":
    both answer UNKNOWN for the same reason, so the green run would prove only
    that an empty object has no attributes. An absent fixture is a missing
    dependency to escalate, not to paper over.
    """
    partial = _FIXTURES / "estate_partial_snapshot.json"
    assert partial.is_file(), (
        f"{partial} is a required fixture: this test names a PARTIAL estate — "
        "vocabularies captured, record tables not — and an empty snapshot "
        "substituted for it cannot distinguish that from a capture that read "
        "nothing at all")
    snapshot = GcpSnapshot.load(partial)
    assert snapshot.captured_categories(), (
        "the partial-estate fixture must have captured SOMETHING, or it is the "
        "empty snapshot this test exists to stop standing in")
    for collection, table in (("firewall_rules", "firewall_rules"),
                              ("hier_firewall_rules",
                               "hierarchical_firewall_policies")):
        records, missing = extract(collection, ctx(snapshot=snapshot))
        assert records == ()
        assert missing == (f"snapshot did not capture {table} — the estate-tier "
                           "rule was not evaluated")


def test_an_estate_rule_abstains_loudly_when_the_table_was_not_captured():
    ast = forall(cmp("eq", fld("action", "f"), lit("Str", "deny")),
                 var="f", coll="firewall_rules")
    rule = sec_rules.CompiledRule(
        promise=promise("estate-deny", "assert_satisfiable", ast, state="estate"))
    verdict = rule.evaluate(ctx(FW_GOOD, "firewall_rule"))
    assert verdict.status == "unverified"
    assert "snapshot did not capture firewall_rules" in verdict.message


def test_an_estate_rule_decides_against_a_captured_table():
    ast = forall({"node": "not", "arg": {"node": "and", "args": [
        cmp("eq", fld("action", "f"), lit("Str", "allow")),
        {"node": "port_in", "term": fld("port", "f"), "lo": 22, "hi": 22},
        {"node": "cidr_contains", "cidr": fld("source_range", "f"),
         "addr": lit("Ip4", "0.0.0.0")},
    ]}}, var="f", coll="firewall_rules")
    rule = sec_rules.CompiledRule(
        promise=promise("estate-no-open-ssh", "assert_satisfiable", ast,
                        state="estate"))
    snapshot = estate_snapshot(firewall_rules=ESTATE_FIREWALL)
    verdict = rule.evaluate(ctx(FW_GOOD, "firewall_rule", snapshot=snapshot))
    if not HAVE_Z3:
        assert verdict.status == "unverified"
        return
    # the captured rule allows tcp/22 only from the IAP range, not from 0/0
    assert verdict.status == "grounded"

    opened = dict(ESTATE_FIREWALL)
    key = "projects/acme-prod/global/firewalls/allow-open-ssh"
    opened[key] = dict(ESTATE_FIREWALL[next(iter(ESTATE_FIREWALL))],
                       source_ranges=["0.0.0.0/0"])
    verdict = rule.evaluate(ctx(FW_GOOD, "firewall_rule",
                                snapshot=estate_snapshot(firewall_rules=opened)))
    assert verdict.status == "contradicted" and "allow-open-ssh" in verdict.message


# =============================================================================
# the domains whose claims module may be absent from this checkout
# =============================================================================

def test_armor_and_vpcsc_collections_exist_even_without_their_modules():
    """A promise naming them compiles; when the module is absent it abstains
    through ``sec_rules``' no-extractor path instead of failing to validate."""
    for name in ("armor_rules", "perimeter_resources",
                 "perimeter_restricted_services"):
        assert name in sec_ast.COLLECTIONS
    ast = exists(cmp("eq", fld("action", "a"), lit("Str", "allow")),
                 var="a", coll="armor_rules")
    sec_ast.validate(ast)
    rule = sec_rules.CompiledRule(
        promise=promise("armor-no-allow", "refute", ast, domain="cloud_armor"))
    verdict = rule.evaluate(ctx({"kind": "compute#securityPolicy"},
                                "security_policy"))
    if "armor_rules" in sec_rules.EXTRACTORS:
        # the module is present in this checkout: the document carries no rules
        assert verdict.status in ("grounded", "unverified")
    else:
        assert verdict.status == "unverified"
        assert "armor_rules" in verdict.message


def test_armor_rules_flatten_per_source_range_when_armor_is_present():
    if "armor_rules" not in sec_rules.EXTRACTORS:
        pytest.skip("armor_claims is not part of this checkout")
    document = {
        "kind": "compute#securityPolicy",
        "name": "edge-waf",
        "rules": [
            {"priority": 1000, "action": "deny-403", "preview": True,
             "match": {"versionedExpr": "SRC_IPS_V1",
                       "config": {"srcIpRanges": ["1.2.3.0/24", "9.9.9.9"]}}},
            {"priority": 2147483647, "action": "allow",
             "match": {"versionedExpr": "SRC_IPS_V1",
                       "config": {"srcIpRanges": ["*"]}}},
        ],
    }
    records, missing = extract("armor_rules", ctx(document, "security_policy"))
    assert missing is None
    assert {(r["priority"], r["src_range"]) for r in records} == {
        (1000, "1.2.3.0/24"), (1000, "9.9.9.9"), (2147483647, "0.0.0.0/0")}
    assert all(r["policy"] == "edge-waf" for r in records)
    # the default rule's "*" arrives already normalized to 0.0.0.0/0, and its
    # mask is the Ip4 companion the cidr_contains encoder needs
    default = next(r for r in records if r["priority"] == 2147483647)
    assert default["src_range_mask"] == "0.0.0.0" and default["preview"] is False


def test_perimeter_extractors_flatten_by_section_when_vpcsc_is_present():
    if "perimeter_resources" not in sec_rules.EXTRACTORS:
        pytest.skip("vpcsc_claims is not part of this checkout")
    document = {
        "name": "accessPolicies/987/servicePerimeters/prod",
        "status": {"resources": ["projects/111"],
                   "restrictedServices": ["storage.googleapis.com"]},
        "spec": {"resources": ["projects/222"],
                 "restrictedServices": ["bigquery.googleapis.com"]},
    }
    context = ctx(document, "vpc_sc_perimeter")
    resources, missing = extract("perimeter_resources", context)
    assert missing is None
    assert {(r["resource"], r["section"]) for r in resources} == {
        ("projects/111", "status"), ("projects/222", "spec")}
    services, missing = extract("perimeter_restricted_services", context)
    assert missing is None
    assert {(r["service"], r["section"]) for r in services} == {
        ("storage.googleapis.com", "status"), ("bigquery.googleapis.com", "spec")}


# =============================================================================
# the named mutation must-kills (MK-I02 .. MK-I13)
#
# Every entry below is a mutation that was MEASURED to survive this suite as it
# stood, re-measured ALONE in an isolated copy of the tree (house rule 7), and is
# killed here by an assertion about BEHAVIOUR — a wrong protocol number, a
# reordered witness, a port that stops being enumerated — never by mirroring the
# mutated literal. Each one changes WHICH promise matches a rule, with no verdict
# text to give it away: RC1 in the packet axis.
# =============================================================================

#: ``(name, its IANA number, the neighbouring number the mutant substitutes)``.
#: The table mutants slide a name onto its neighbour's number, so each name is
#: pinned twice: by the number a rule ENCODES, and by a promise about the
#: neighbour protocol that must NOT match that rule.
PROTOCOL_PINS = (("icmp", 1, 2), ("udp", 17, 18), ("ipv6-icmp", 58, 59))


@pytest.mark.parametrize("name, iana, neighbour", PROTOCOL_PINS)
def test_a_protocol_name_encodes_its_own_iana_number(name, iana, neighbour):
    """MK-I02 / MK-I03 / MK-I04 (sec_domains.py:171-172).

    The table IS the mapping from what a rule says to what a promise reasons
    over: ``icmp`` -> 1, ``udp`` -> 17, ``ipv6-icmp`` -> 58. Move one entry onto
    its neighbour and an icmp rule starts answering an igmp promise — silently,
    because no verdict text ever mentions a protocol number."""
    assert sec_domains.PROTOCOL_NUMBERS[name] == iana

    doc = dict(two_by_two(), allowed=[{"IPProtocol": name}])
    records, missing = extract("proposed_firewall_rules", ctx(doc, "firewall_rule"))
    assert missing is None
    assert {r["protocol"] for r in records} == {iana}

    # end-to-end: "no rule speaks the NEIGHBOUR protocol" holds over a document
    # whose only rule speaks THIS one.
    about_neighbour = sec_rules.CompiledRule(
        promise=promise(f"no-proto-{neighbour}", "refute",
                        exists(cmp("eq", fld("protocol"), lit("Proto", neighbour)))))
    verdict = about_neighbour.evaluate(ctx(doc, "firewall_rule"))
    if not HAVE_Z3:
        assert verdict.status == "unverified"
        return
    assert verdict.status == "grounded" and verdict.kind == "sec:vpc_firewall"


def normalized_rule(**overrides):
    """A normalized VPC firewall rule — the shape a claim payload hands the
    flattener, built here rather than parsed so one dimension can be varied."""
    rule = {"network": "projects/acme-prod/global/networks/vpc-main",
            "direction": "INGRESS", "action": "allow", "priority": 1000,
            "disabled": False, "source_ranges": ["10.0.0.0/8"],
            "layer4": [{"protocol": "tcp", "ports": ["22"]}]}
    rule.update(overrides)
    return rule


def test_a_row_missing_a_field_sorts_after_every_row_that_carries_it():
    """MK-I05 (sec_domains.py:225): the rank that puts a PRESENT field first.

    Rows are deliberately ragged, so the sort key must be total. The docstring
    promises an absent key sorts AFTER every present one; the mutant collapses
    the two ranks, so an absent key sorts BEFORE every present one and silently
    reorders the records a witness is drawn from."""
    ragged = normalized_rule(layer4=[{"protocol": "tcp", "ports": ["22"]},
                                     {"protocol": "tcp"}])
    records = sec_domains._firewall_records([("fw-ragged", ragged)], "firewall rule")

    assert len(records) == 2
    assert records[0]["port"] == 22
    assert "port" not in records[-1]

    # the same rank, stated directly and independent of every other field
    assert sec_domains._sorted([{}, {"port": 22}], {"port": "Port"}) == (
        {"port": 22}, {})


def test_a_string_dimension_takes_real_strings_and_nothing_else():
    """MK-I06 (sec_domains.py:254): ``isinstance(v, str) and v``.

    The module RESERVES the empty string for an honest "no tag". Under the mutant
    an empty string and any truthy non-string enter the dimension, so a rule with
    no tags grows rows claiming a tag it does not have."""
    assert sec_domains._str_dimension("source_tag", ["", "web", 7]) == [
        {"source_tag": "web"}]
    # the reserved fallback applies only when NOTHING survives the filter
    assert sec_domains._str_dimension("source_tag", []) == [{"source_tag": ""}]
    assert sec_domains._str_dimension("source_tag", ["", 7]) == [{"source_tag": ""}]

    tagged = normalized_rule(source_tags=["", "web"])
    records = sec_domains._firewall_records([("fw-tags", tagged)], "firewall rule")
    assert {r["source_tag"] for r in records} == {"web"}


def test_an_all_protocols_rule_omits_the_protocol_key_and_still_evaluates():
    """MK-I07 (sec_domains.py:290): ``protocol is None or protocol == "all"``.

    Both spellings of "every protocol" omit the key, so a protocol-free promise
    still judges the rule and a protocol-mentioning one abstains loudly. Under
    the mutant BOTH fall through to the undecidable, so every all-protocols rule
    makes its whole collection abstain instead."""
    for block in ({"protocol": "all", "ports": ["22"]}, {"ports": ["22"]}):
        assert sec_domains._layer4_dimension("firewall rule", "fw-all",
                                             [block]) == [{"port": 22}]

    records = sec_domains._firewall_records(
        [("fw-all", normalized_rule(layer4=[{"protocol": "all", "ports": ["22"]}]))],
        "firewall rule")
    assert records and all("protocol" not in r for r in records)
    assert {r["port"] for r in records} == {22}    # the rule was still evaluated


def test_protocol_zero_is_hopopt_and_is_a_legal_value():
    """MK-I08 (sec_domains.py:302): the lower protocol-number bound.

    0 is HOPOPT, a real IANA protocol. The mutant rejects it, so a rule naming it
    abstains for a reason that is not true."""
    assert sec_domains._protocol_number("firewall rule", "fw-hop", 0) == 0
    assert sec_domains._protocol_number("firewall rule", "fw-hop", "0") == 0
    assert sec_domains._layer4_dimension(
        "firewall rule", "fw-hop", [{"protocol": 0, "ports": ["22"]}]) == [
            {"protocol": 0, "port": 22}]


def test_a_range_of_exactly_the_maximum_span_is_still_enumerated():
    """MK-I09 (sec_domains.py:321): ``high - low + 1 > MAX_PORT_SPAN``.

    A REAL BOUNDARY. A range spanning exactly the maximum is enumerable by
    definition; the mutant treats it as wide and stops enumerating it, so every
    port in it silently drops out of the instance."""
    span = sec_domains.MAX_PORT_SPAN
    exact = sec_domains._port_values("firewall rule", "fw-span", [f"0-{span - 1}"])
    assert len(exact) == span
    assert exact[0] == 0 and exact[-1] == span - 1
    assert None not in exact                       # nothing was omitted

    wider = sec_domains._port_values("firewall rule", "fw-span", [f"0-{span}"])
    assert wider == [None]                         # one port wider IS omitted


def test_a_wide_port_range_omits_the_port_key_so_a_port_promise_abstains():
    """MK-I10 (sec_domains.py:324): the ``wide`` flag.

    THE HIGHEST-VALUE ENTRY IN EITHER LIST. With the flag never set the
    port-key-omitted row is never appended, so a promise about a specific port
    UNDER-MATCHES a wide range: it reads the enumerated ports, never sees the
    65 000 that were dropped, and grounds. Omitting the key is what makes it
    abstain loudly instead."""
    mixed = sec_domains._port_values("firewall rule", "fw-wide", ["22", "0-65535"])
    assert mixed == [22, None]

    doc = dict(two_by_two(), allowed=[{"IPProtocol": "tcp",
                                       "ports": ["22", "0-65535"]}])
    records, missing = extract("proposed_firewall_rules", ctx(doc, "firewall_rule"))
    assert missing is None
    assert [r for r in records if "port" not in r], "a wide range yields a portless row"

    about_port_80 = sec_rules.CompiledRule(
        promise=promise("no-port-80", "refute",
                        exists({"node": "port_in", "term": fld("port"),
                                "lo": 80, "hi": 80})))
    wide = about_port_80.evaluate(ctx(doc, "firewall_rule"))
    narrow = about_port_80.evaluate(
        ctx(dict(two_by_two(), allowed=[{"IPProtocol": "tcp", "ports": ["22"]}]),
            "firewall_rule"))
    if not HAVE_Z3:
        assert wide.status == "unverified" and narrow.status == "unverified"
        return
    # the control: with every port enumerated the SAME promise decides
    assert narrow.status == "grounded"
    # and over the wide range it abstains loudly instead of under-matching
    assert wide.status == "unverified" and wide.status != "grounded"
    assert "port is missing from the record" in wide.message


def test_port_zero_is_a_legal_port():
    """MK-I11 (sec_domains.py:342): the FIRST comparison of the port bound.

    The mutant makes port 0 abstain, so a rule mentioning it stops being
    evaluated at all."""
    assert sec_domains._port_bounds("firewall rule", "fw-zero", "0") == (0, 0)
    assert sec_domains._port_bounds("firewall rule", "fw-zero", "0-10") == (0, 10)
    assert sec_domains._port_values("firewall rule", "fw-zero", ["0"]) == [0]


def test_the_last_port_is_65535_and_one_past_it_abstains_by_name():
    """MK-I12 (sec_domains.py:342): the port upper bound.

    Relaxing it accepts an impossible port and encodes it as though it were
    real, instead of naming it in an abstention."""
    assert sec_domains._port_bounds("firewall rule", "fw-top", "65535") == (65535,
                                                                            65535)
    with pytest.raises(sec_domains._Undecidable) as excinfo:
        sec_domains._port_bounds("firewall rule", "fw-top", "65536")
    assert "65536" in str(excinfo.value)
    assert "outside" in str(excinfo.value) and "not evaluated" in str(excinfo.value)


def test_a_crashing_domain_extractor_logs_its_traceback(caplog):
    """MK-I13 (sec_domains.py:548): the ``exc_info=True`` of the extractor-failed
    debug log.

    The broad arm swallows the exception BY CONTRACT — a crashing domain module
    must not break the gate — so the traceback in the log is the only record of
    where it actually broke. NOTE THE TRAP: ``exc_info=False`` leaves a record
    whose ``exc_info`` is ``False``, which passes an ``is not None`` check while
    printing no traceback at all. So the assertion is on TRUTH, and on the
    exception the record carries."""
    def boom(_ctx):
        raise ValueError("the payload shape changed under us")

    log = logging.getLogger(sec_domains.logger.name)
    log.addHandler(caplog.handler)
    propagate = log.propagate
    log.propagate = False       # exactly one copy, whatever the embedder set up
    try:
        with caplog.at_level(logging.DEBUG, logger=log.name):
            records, missing = sec_domains._guarded("armor_rules", boom)(None)
    finally:
        log.propagate = propagate
        log.removeHandler(caplog.handler)

    assert records == ()
    assert "armor_rules" in missing and "the payload shape changed under us" in missing

    [record] = [r for r in caplog.records if r.name == log.name]
    assert record.exc_info                      # TRUTHY, never `is not None`
    assert record.exc_info[0] is ValueError


# =============================================================================
# record-shape guards in the collection extractors
#
# Every guard below turns a GENERIC floor abstention — "the extractor produced no
# records and did not say whether the collection is empty or unreadable" — into a
# PRECISE one at the site that produced it, naming the record and the key it
# could not read. Each shape was MEASURED to yield zero records and NO reason
# before its guard landed, and zero records with no reason is exactly the state
# in which a ``forall`` promise passes over rows nobody ever read.
# =============================================================================

#: An override that DELETES a key rather than setting it — the measured shape is
#: a policy record carrying only an attachments list.
_ABSENT = object()

HIER_POLICY = "organizations/1/locations/global/firewallPolicies/fp-baseline"

#: "every hierarchical rule is attached to organizations/1" — a NODE-SCOPED
#: promise, which is the shape an unreadable ``attachments`` key lets pass while
#: the policy is in fact attached to the organization.
NODE_FORALL = forall(cmp("eq", fld("node", "h"), lit("Str", "organizations/1")),
                     var="h", coll="hier_firewall_rules")


def hier_table(**overrides):
    """The captured policies table holding ONE policy, with one key varied."""
    record = dict(ESTATE_HIER[HIER_POLICY], **overrides)
    return {HIER_POLICY: {k: v for k, v in record.items() if v is not _ABSENT}}


def hier_extract(table):
    return extract("hier_firewall_rules", ctx(snapshot=estate_snapshot(
        hierarchical_firewall_policies=table)))


def hier_verdict(table, pid):
    """The end-to-end verdict of the node-scoped promise over *table*."""
    rule = sec_rules.CompiledRule(
        promise=promise(pid, "assert_satisfiable", NODE_FORALL,
                        domain="hier_firewall", state="estate"))
    return rule.evaluate(ctx(kind="firewall_policy", snapshot=estate_snapshot(
        hierarchical_firewall_policies=table)))


@pytest.mark.parametrize("rules", [_ABSENT, {"0": {"action": "deny"}}, "deny-all"])
def test_a_policy_whose_rules_key_is_unreadable_abstains_naming_policy_and_key(rules):
    """MEASURED before the guard: a table holding one policy with only an
    attachments list yields zero records and no missing reason, and so does the
    same table with ``rules`` as a Mapping."""
    records, missing = hier_extract(hier_table(rules=rules))
    assert records == ()
    assert missing and "fp-baseline" in missing and "'rules'" in missing

    verdict = hier_verdict(hier_table(rules=rules), "hier-rules-shape")
    assert verdict.status == "unverified" and verdict.status != "grounded"
    assert "fp-baseline" in verdict.message


@pytest.mark.parametrize("attachments", [_ABSENT, "organizations/1",
                                         {"0": "organizations/1"}])
def test_a_policy_whose_attachments_are_unreadable_abstains_naming_policy_and_key(
        attachments):
    """ATTACHMENTS ARE A SCOPE SELECTOR, NOT A TAG.

    Encoded as the reserved empty string, a policy that IS attached to an
    organization reads as attached NOWHERE, and the node-scoped promise above
    passes over a rule that violates it."""
    records, missing = hier_extract(hier_table(attachments=attachments))
    assert records == ()
    assert missing and "fp-baseline" in missing and "'attachments'" in missing

    verdict = hier_verdict(hier_table(attachments=attachments), "hier-attach-shape")
    assert verdict.status == "unverified" and verdict.status != "grounded"
    assert "fp-baseline" in verdict.message


def test_a_captured_empty_attachment_list_keeps_the_honest_empty_string():
    """The empty string stays RESERVED for a genuinely captured empty list — a
    policy attached nowhere is a fact about the estate, not a hole in it."""
    records, missing = hier_extract(hier_table(attachments=[]))
    assert missing is None
    assert records and all(record["node"] == "" for record in records)

    verdict = hier_verdict(hier_table(attachments=[]), "hier-attach-empty")
    if not HAVE_Z3:
        assert verdict.status == "unverified"
        return
    # attached nowhere is DECIDABLE, and it refutes the node-scoped promise
    assert verdict.status == "contradicted"


def test_an_unsupported_policy_record_is_rejected_before_the_rules_loop():
    """Dropping the policy would let a ``forall`` promise pass vacuously, which
    the clause forbids — so the rejector runs on the POLICY record itself, not
    only on each rule inside it."""
    table = hier_table(unsupported="the policy carried a shape we do not model")
    records, missing = hier_extract(table)
    assert records == ()
    assert missing and "fp-baseline" in missing
    assert "not fully understood" in missing

    verdict = hier_verdict(table, "hier-unsupported")
    assert verdict.status == "unverified" and verdict.status != "grounded"


def test_a_non_empty_policy_table_that_produced_no_rows_abstains_precisely():
    """A captured-but-ruleless table is vacuity the generic floor catches LATE
    and anonymously; the extractor names the table instead."""
    records, missing = hier_extract(hier_table(rules=[]))
    assert records == ()
    assert missing and "hierarchical_firewall_policies" in missing
    assert "did not say whether" not in missing     # not the generic floor text

    verdict = hier_verdict(hier_table(rules=[]), "hier-no-rows")
    assert verdict.status == "unverified" and verdict.status != "grounded"


def test_the_control_a_readable_policy_table_still_grounds_the_node_promise():
    """Without this, every assertion above could be satisfied by an extractor
    that abstains on everything."""
    records, missing = hier_extract(hier_table())
    assert missing is None and records

    verdict = hier_verdict(hier_table(), "hier-node-control")
    if not HAVE_Z3:
        assert verdict.status == "unverified"
        return
    assert verdict.status == "grounded"


# -- perimeter sections -------------------------------------------------------

#: collection -> the ``(field, payload key, field table)`` triple ``register``
#: passes ``_perimeter_entries``, so the guards are pinned on exactly the
#: extractor a checkout carrying ``vpcsc_claims`` installs.
PERIMETER_SHAPES = {
    "perimeter_resources": ("resource", "resources",
                            sec_domains._PERIMETER_RESOURCE_FIELDS),
    "perimeter_restricted_services": ("service", "restricted_services",
                                      sec_domains._PERIMETER_SERVICE_FIELDS),
}

PERIMETER_DOC = {"name": "accessPolicies/987/servicePerimeters/prod"}

#: "every perimeter entry is enforced, not dry-run" — the promise a silently
#: skipped section makes pass over entries nobody read.
SECTION_FORALL = forall(cmp("eq", fld("section", "p"), lit("Str", "status")),
                        var="p", coll="perimeter_resources")


def perimeter_claim(name, **payload):
    """One ``perimeter_config`` claim in the normalized snake_case shape."""
    return Claim.of("perimeter_config",
                    f"accessPolicies/987/servicePerimeters/{name}",
                    "$.name", name=name, **payload)


def perimeter_extract(claims, collection="perimeter_resources"):
    """The guarded extractor for *collection*, over a stand-in claims module so
    the shape is pinned in a checkout that does not carry ``vpcsc_claims``."""
    module = SimpleNamespace(
        DOCUMENT_EXTRACTORS={"vpc_sc_perimeter": lambda _doc: list(claims)})
    field, source, fields = PERIMETER_SHAPES[collection]
    return sec_domains._guarded(
        collection,
        sec_domains._perimeter_entries(module, collection, field, source, fields))


def perimeter_verdict(claims, pid):
    """The end-to-end verdict of the enforced-section promise over *claims*."""
    sec_rules.register_extractor("perimeter_resources", perimeter_extract(claims))
    rule = sec_rules.CompiledRule(
        promise=promise(pid, "assert_satisfiable", SECTION_FORALL, domain="vpc_sc"))
    return rule.evaluate(ctx(PERIMETER_DOC, "vpc_sc_perimeter"))


def test_a_perimeter_carrying_neither_spec_nor_status_abstains_by_name():
    """MEASURED before the guard: the extractor skips any section block that is
    not a Mapping and returns zero records with no reason."""
    claims = [perimeter_claim("prod")]
    records, missing = perimeter_extract(claims)(ctx(PERIMETER_DOC,
                                                     "vpc_sc_perimeter"))
    assert records == ()
    assert missing and "prod" in missing
    assert "spec" in missing and "status" in missing

    verdict = perimeter_verdict(claims, "vpcsc-no-section")
    assert verdict.status == "unverified" and verdict.status != "grounded"
    assert "prod" in verdict.message


@pytest.mark.parametrize("collection", sorted(PERIMETER_SHAPES))
@pytest.mark.parametrize("section", ["spec", "status"])
def test_a_perimeter_section_without_its_entry_key_abstains_by_name(section,
                                                                   collection):
    """The hard-coded entry key was read raw, so any payload drift produced zero
    records and no reason. Both extractors, both sections."""
    _field, source, _fields = PERIMETER_SHAPES[collection]
    claims = [perimeter_claim("prod", **{section: {"unrelated": []}})]
    records, missing = perimeter_extract(claims, collection)(
        ctx(PERIMETER_DOC, "vpc_sc_perimeter"))
    assert records == ()
    assert missing and "prod" in missing and section in missing
    assert repr(source) in missing

    if collection != "perimeter_resources":
        return                       # the promise below quantifies over that one
    verdict = perimeter_verdict(claims, f"vpcsc-no-{section}-key")
    assert verdict.status == "unverified" and verdict.status != "grounded"
    assert "prod" in verdict.message and repr(source) in verdict.message


def test_a_non_empty_perimeter_claim_list_that_produced_no_rows_abstains():
    claims = [perimeter_claim("prod", status={"resources": []})]
    records, missing = perimeter_extract(claims)(ctx(PERIMETER_DOC,
                                                     "vpc_sc_perimeter"))
    assert records == ()
    assert missing and "perimeter_resources" in missing
    assert "did not say whether" not in missing     # not the generic floor text

    verdict = perimeter_verdict(claims, "vpcsc-no-rows")
    assert verdict.status == "unverified" and verdict.status != "grounded"


def test_a_spec_only_perimeter_is_not_read_as_enforced():
    """The section is a real dimension: conflating the dry-run half with the
    enforced one would let a spec-only change read as enforced."""
    claims = [perimeter_claim("prod", spec={"resources": ["projects/222"]})]
    records, missing = perimeter_extract(claims)(ctx(PERIMETER_DOC,
                                                     "vpc_sc_perimeter"))
    assert missing is None
    assert [record["section"] for record in records] == ["spec"]

    verdict = perimeter_verdict(claims, "vpcsc-spec-only")
    if not HAVE_Z3:
        assert verdict.status == "unverified"
        return
    assert verdict.status == "contradicted"


def test_the_control_a_readable_perimeter_still_flattens_and_grounds():
    claims = [perimeter_claim(
        "prod", status={"resources": ["projects/111"],
                        "restricted_services": ["storage.googleapis.com"]})]
    records, missing = perimeter_extract(claims)(ctx(PERIMETER_DOC,
                                                     "vpc_sc_perimeter"))
    assert missing is None
    assert [dict(record) for record in records] == [
        {"perimeter": "prod", "resource": "projects/111", "section": "status"}]

    services, missing = perimeter_extract(
        claims, "perimeter_restricted_services")(ctx(PERIMETER_DOC,
                                                     "vpc_sc_perimeter"))
    assert missing is None
    assert [record["service"] for record in services] == ["storage.googleapis.com"]

    verdict = perimeter_verdict(claims, "vpcsc-control")
    if not HAVE_Z3:
        assert verdict.status == "unverified"
        return
    assert verdict.status == "grounded"


# -- the two guards mutation proved untested, and the crash channel -----------


def test_a_source_range_that_is_not_ipv4_abstains_with_the_range_named():
    """MUTATION-PROVED UNTESTED, and RE-MEASURED here: replacing
    ``_cidr_dimension``'s abstain arm with ``continue`` (line-count neutral, so
    the evidence-lint anchors do not move) SURVIVES the whole suite with this
    test deselected and is KILLED by it.

    A rule whose source ranges are ALL non-IPv4 must NAME the range it could not
    read; dropping the range instead leaves a rangeless row a cidr-mentioning
    promise judges as though the rule's scope had been established."""
    with pytest.raises(sec_domains._Undecidable) as excinfo:
        sec_domains._firewall_records(
            [("fw-v6", normalized_rule(source_ranges=["2001:db8::/32"]))],
            "firewall rule")
    assert "2001:db8::/32" in str(excinfo.value) and "fw-v6" in str(excinfo.value)
    assert "not evaluated" in str(excinfo.value)

    doc = dict(two_by_two(), sourceRanges=["2001:db8::/32"])
    records, missing = extract("proposed_firewall_rules", ctx(doc, "firewall_rule"))
    assert records == () and "2001:db8::/32" in missing
    # the control: the same document with an IPv4 range reads its rows
    ipv4, ipv4_missing = extract("proposed_firewall_rules",
                                 ctx(two_by_two(), "firewall_rule"))
    assert ipv4_missing is None and ipv4

    rule = sec_rules.CompiledRule(promise=promise("no-open-ssh-v6", "refute",
                                                  OPEN_SSH))
    verdict = rule.evaluate(ctx(doc, "firewall_rule"))
    assert verdict.status == "unverified" and "2001:db8::/32" in verdict.message
    if not HAVE_Z3:
        return
    # and the control end-to-end: the same promise still decides a readable rule
    assert rule.evaluate(ctx(FW_GOOD, "firewall_rule")).status == "grounded"


def test_a_narrow_port_beside_an_over_wide_range_yields_both_rows():
    """The wide range contributes a PORT-OMITTED row BESIDE the enumerated one,
    so a promise about the SPECIFIC port abstains loudly instead of grounding
    over an instance the 65 000 dropped ports never entered.

    MEASURED, and stated rather than claimed: in THIS checkout the port-value
    mutants of that shape (``values.append(None)`` dropped, moved to the front,
    or made to replace the enumerated ports; the append made conditional on
    nothing having been enumerated) are ALREADY killed by MK-I10 above, which
    pins ``_port_values(["22", "0-65535"]) == [22, None]``. What this test adds
    is the consequence MK-I10 does not reach: MK-I10 asks about port 80, which
    the rule never enumerates, while a promise about port 22 — the port the rule
    DOES carry — must still abstain, because the wide range means the instance
    cannot answer for it either way."""
    doc = dict(two_by_two(),
               allowed=[{"IPProtocol": "tcp", "ports": ["22", "0-65535"]}])
    records, missing = extract("proposed_firewall_rules", ctx(doc, "firewall_rule"))
    assert missing is None
    assert [r for r in records if r.get("port") == 22], "the narrow port is a row"
    assert [r for r in records if "port" not in r], "the wide range is a row too"

    about_22 = sec_rules.CompiledRule(
        promise=promise("some-rule-allows-22", "assert_satisfiable",
                        exists({"node": "port_in", "term": fld("port"),
                                "lo": 22, "hi": 22})))
    wide = about_22.evaluate(ctx(doc, "firewall_rule"))
    narrow = about_22.evaluate(
        ctx(dict(two_by_two(), allowed=[{"IPProtocol": "tcp", "ports": ["22"]}]),
            "firewall_rule"))
    if not HAVE_Z3:
        assert wide.status == "unverified" and narrow.status == "unverified"
        return
    assert narrow.status == "grounded"       # the control: it CAN decide
    assert wide.status == "unverified" and wide.status != "grounded"
    assert "port is missing from the record" in wide.message


def test_a_crashing_extractor_abstains_by_collection_and_the_rule_does_not_raise():
    """The broad arm of ``_guarded`` is load-bearing: narrowing it to a class the
    suite never raises survives every other test here.

    A plain ``RuntimeError`` — no domain type, no evidence type — must still
    become one abstention naming the collection, and rule evaluation must RETURN
    that abstention rather than let the exception escape into the gate."""
    def boom(_ctx):
        raise RuntimeError("the estate table changed shape under us")

    sec_rules.register_extractor("firewall_rules",
                                 sec_domains._guarded("firewall_rules", boom))
    records, missing = extract("firewall_rules", ctx())
    assert records == ()
    assert "firewall_rules" in missing
    assert "the estate table changed shape under us" in missing

    ast = forall(cmp("eq", fld("action", "f"), lit("Str", "deny")),
                 var="f", coll="firewall_rules")
    rule = sec_rules.CompiledRule(
        promise=promise("estate-crash", "assert_satisfiable", ast, state="estate"))
    verdict = rule.evaluate(ctx(FW_GOOD, "firewall_rule"))      # must not raise
    assert verdict.status == "unverified"
    assert "firewall_rules" in verdict.message
    assert "the estate table changed shape under us" in verdict.message
