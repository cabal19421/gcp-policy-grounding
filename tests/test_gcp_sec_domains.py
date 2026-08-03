"""Tests for :mod:`gcp_grounding.sec_domains`.

HAVE_Z3-branched in the idiom of the encode/probes/rules suites: rather than
*skip* the solver-dependent cases on the builtin backend, each test asserts the
documented builtin behaviour (every rule abstains ``unverified``) when z3 is
absent and the real grounded/contradicted assertions when it is present.

The estate cases are ALSO checkout-branched. The estate snapshot tables
(``firewall_rules``, ``hierarchical_firewall_policies``) and the
``estate_partial_snapshot.json`` fixture arrive with ``sx-kb-estate-tables`` /
``sx-fixtures-estate``; :func:`estate_snapshot` builds a real
:class:`~gcp_grounding.knowledge.GcpSnapshot` when those fields exist and a
stand-in object with the same attributes when they do not, so the extractor's
``getattr``-and-compare-with-``is`` contract is exercised either way.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from gcp_grounding import (sec_artifact, sec_ast, sec_domains, sec_encode,
                           sec_probes, sec_rules, solve)
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


# =============================================================================
# registration
# =============================================================================

def test_register_is_idempotent(monkeypatch):
    """The second call registers nothing — asserted by a counter."""
    sec_domains.reset()
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
    assert first["extractors"] >= 2  # the two estate collections always register
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


def test_a_terraform_plan_reaches_the_firewall_claims_through_the_registry():
    plan = json.loads((_POLICIES / "fw_tf_plan.json").read_text())
    records, missing = extract("proposed_firewall_rules", ctx(plan, "tf_plan"))
    assert missing is None or "was not fully understood" in missing
    if missing is None:
        assert records, "a plan carrying a google_compute_firewall yields rows"


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
    table; without that fixture a bare snapshot is the same 'not captured'."""
    partial = _FIXTURES / "estate_partial_snapshot.json"
    snapshot = GcpSnapshot.load(partial) if partial.exists() else SNAP
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
