"""Tests for the two IAM deny-policy proposal collections (F1 of the deny pair).

``deny_rules`` flattens one row per EFFECTIVE (rule, denied-principal,
denied-permission) combination — permission exceptions subtracted before rows
exist — and ``deny_rule_exceptions`` enumerates the principal carve-outs.
This module pins the row sets for every committed deny fixture, every named
abstention path (unnormalizable permission, malformed census, plan census,
count/for_each, off-kind documents), the observed-empty attestation of an
exception-free policy, and the strong worked promise end-to-end through
:meth:`gcp_grounding.sec_rules.CompiledRule.evaluate`.

HAVE_Z3-branched in the idiom of tests/test_gcp_sec_domains.py: the
solver-dependent promise cases assert the documented builtin behaviour (the
rule abstains ``unverified`` naming the absent z3) when z3 is missing and the
real grounded/contradicted buckets when it is present. The extractors
themselves are solver-free and asserted unbranched.

NAMED MUTATION MUST-KILLS PINNED HERE: MK-D01 (the exception subtraction),
MK-D02 (the has_principal_exceptions bool), MK-D03 (the unnormalizable-
permission abort), MK-D04 (the plan census), MK-D05 (the unreadable-condition
key omission). Each was measured against a copy of this tree with the mutant
applied alone before being seeded — see tests/mutation_entries.py's
DENY_ENTRIES block for the register-side story.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gcp_grounding import (evidence, sec_artifact, sec_ast, sec_domains,
                           sec_encode, sec_probes, sec_rules)
from gcp_grounding import iam_deny
from gcp_grounding.claims import Claim
from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot

_SOLVER = get_solver()
Z3 = _z3_module(_SOLVER)
HAVE_Z3 = _SOLVER.backend == "z3"

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

SNAP = GcpSnapshot.load(FIXTURES / "snapshot_deny_estate.json")

STRONG = json.loads((POLICIES / "deny_policy_strong.json").read_text())
THREADED = json.loads((POLICIES / "deny_policy_threaded.json").read_text())
CONDITIONAL = json.loads((POLICIES / "deny_policy_conditional.json").read_text())
MALFORMED = json.loads((POLICIES / "deny_policy_malformed.json").read_text())
PLAN = json.loads((POLICIES / "plan_deny_and_grant.json").read_text())

TOKEN = "iam.serviceAccounts.getAccessToken"
PUBLIC_ALL = "principalSet://goog/public:all"
BREAKGLASS = "principal://goog/subject/breakglass@acme.example"


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


def ctx(document=None, kind=None, *, snapshot=SNAP):
    return sec_rules.RuleContext(snapshot=snapshot, document=document,
                                 document_kind=kind)


def extract(collection, context):
    """→ (records, missing_reason, empty_because), through the floor."""
    result = sec_rules.EXTRACTORS[collection](context)
    return sec_rules._normalize_extraction(collection, result)


def deny_rows(document, kind="iam_deny_policy"):
    return extract("deny_rules", ctx(document, kind))


def exception_rows(document, kind="iam_deny_policy"):
    return extract("deny_rule_exceptions", ctx(document, kind))


# -- registration ---------------------------------------------------------


def test_the_two_deny_collections_are_registered_proposal_tier():
    for name in ("deny_rules", "deny_rule_exceptions"):
        assert sec_ast.COLLECTIONS[name].tier == "proposal"
        assert name in sec_rules.EXTRACTORS
    assert sec_domains.DOMAIN_COLLECTIONS["iam"] == (
        "proposed_role_permissions", "deny_rules", "deny_rule_exceptions")
    fields = sec_ast.COLLECTIONS["deny_rules"].fields
    assert fields == {"policy": "Str", "rule_index": "Int",
                      "denied_principal": "Str", "permission": "Str",
                      "has_principal_exceptions": "Bool",
                      "has_condition": "Bool", "condition": "Str"}
    assert sec_ast.COLLECTIONS["deny_rule_exceptions"].fields == {
        "policy": "Str", "rule_index": "Int", "exception_principal": "Str"}


# -- the REST row sets -----------------------------------------------------


def test_strong_policy_flattens_to_the_one_effective_row():
    records, missing, empty = deny_rows(STRONG)
    assert missing is None and empty is None
    assert records == ({
        "policy": STRONG["name"], "rule_index": 0,
        "denied_principal": PUBLIC_ALL, "permission": TOKEN,
        "has_principal_exceptions": False,
        "has_condition": False, "condition": "",
    },)


def test_permission_exceptions_are_subtracted_before_rows_exist():
    """MK-D01's behaviour: the threaded fixture's rule 1 denies two
    permissions and excepts the token one back — the surviving row names ONLY
    the key-creation permission, because a row for the excepted one would
    state a falsehood a forall promise could be refuted by."""
    records, missing, _ = deny_rows(THREADED)
    assert missing is None
    rule1 = [r for r in records if r["rule_index"] == 1]
    assert [r["permission"] for r in rule1] == ["iam.serviceAccountKeys.create"]
    assert all(TOKEN != r["permission"] for r in rule1)


def test_principal_exceptions_set_the_bool_and_mint_exception_rows():
    """MK-D02's behaviour on the rule with a carve-out, and the joinable
    second collection carrying WHO is exempted in the raw v2 spelling."""
    records, missing, _ = deny_rows(THREADED)
    assert missing is None
    by_rule = {r["rule_index"]: r["has_principal_exceptions"] for r in records}
    assert by_rule == {0: True, 1: False}
    exceptions, missing, empty = exception_rows(THREADED)
    assert missing is None and empty is None
    assert exceptions == ({
        "policy": THREADED["name"], "rule_index": 0,
        "exception_principal": BREAKGLASS,
    },)


def test_an_exception_free_policy_attests_observed_emptiness():
    records, missing, empty = exception_rows(STRONG)
    assert records == () and missing is None
    assert "every deny rule was read and none carries a principal exception" \
        in empty


def test_a_readable_condition_is_both_flag_and_raw_text():
    records, missing, _ = deny_rows(CONDITIONAL)
    assert missing is None
    (row,) = records
    assert row["has_condition"] is True
    assert row["condition"] == "request.time < timestamp('2027-01-01T00:00:00Z')"


def test_an_unreadable_condition_block_omits_both_keys():
    """MK-D05's behaviour: a denialCondition block that is present but carries
    no readable expression omits BOTH condition keys, so "denies …
    unconditionally" abstains loudly while permission-only promises still
    judge the rule."""
    doc = json.loads(json.dumps(STRONG))
    doc["rules"][0]["denyRule"]["denialCondition"] = {"title": "no expression"}
    records, missing, _ = deny_rows(doc)
    assert missing is None
    (row,) = records
    assert "has_condition" not in row and "condition" not in row
    assert row["permission"] == TOKEN  # the rule is still visible


def test_an_empty_denied_principal_list_omits_the_key_not_the_rule():
    doc = json.loads(json.dumps(STRONG))
    doc["rules"][0]["denyRule"]["deniedPrincipals"] = []
    records, missing, _ = deny_rows(doc)
    assert missing is None
    (row,) = records
    assert "denied_principal" not in row
    assert row["permission"] == TOKEN


# -- the named abstentions -------------------------------------------------


def test_a_wildcard_permission_aborts_the_rule_naming_the_raw_string():
    """MK-D03's behaviour: an entry with no unambiguous normalized form aborts
    the whole rule by name — dropping only the bad entry would let a forall
    pass over a permission nobody read."""
    doc = json.loads(json.dumps(STRONG))
    doc["rules"][0]["denyRule"]["deniedPermissions"] = [
        "iam.googleapis.com/roles.*"]
    records, missing, _ = deny_rows(doc)
    assert records == ()
    assert missing is not None
    assert "iam.googleapis.com/roles.*" in missing
    assert "no unambiguous normalized form" in missing


def test_the_malformed_fixture_aborts_naming_the_unread_entry():
    records, missing, _ = deny_rows(MALFORMED)
    assert records == ()
    assert missing is not None
    assert "rules[0]" in missing and "deniedPermissions" in missing
    assert "fabricate a refutation" in missing


def test_a_non_list_principal_field_aborts_by_name():
    doc = json.loads(json.dumps(STRONG))
    doc["rules"][0]["denyRule"]["deniedPrincipals"] = "principalSet://goog/public:all"
    records, missing, _ = deny_rows(doc)
    assert records == ()
    assert missing is not None and "deniedPrincipals" in missing


def test_an_iam_allow_policy_is_the_honest_off_kind_abstention():
    records, missing, _ = deny_rows({"bindings": []}, kind="iam_policy")
    assert records == ()
    assert "not an IAM deny policy" in missing


def test_a_rule_index_payload_that_disagrees_with_its_location_aborts():
    claims = (Claim.of("denied_permission",
                       "iam.googleapis.com/serviceAccounts.getAccessToken",
                       "rules[0].denyRule.deniedPermissions[0]",
                       rule_index=5, excepted=False),)
    with pytest.raises(sec_domains._Undecidable) as exc:
        sec_domains._deny_groups(claims, {"": STRONG}, iam_deny)
    assert "rule_index=5" in str(exc.value)
    assert "disagrees with its own location" in str(exc.value)


# -- the terraform arm -----------------------------------------------------


def test_the_plan_arm_threads_the_block_address_and_no_policy_name():
    records, missing, _ = deny_rows(PLAN, kind="tf_plan")
    assert missing is None
    (row,) = records
    assert row[sec_rules.WITNESS_ADDRESS_FIELD] == \
        "google_iam_deny_policy.guardrail"
    assert row["policy"] == ""  # a plan's literal name is not trusted
    assert row["permission"] == TOKEN
    assert row["denied_principal"] == PUBLIC_ALL


def test_rest_and_terraform_rows_agree_on_the_shared_fields():
    rest, _m, _e = deny_rows(STRONG)
    tf, _m2, _e2 = deny_rows(PLAN, kind="tf_plan")
    strip = lambda row: {k: v for k, v in row.items()
                         if k not in ("policy", sec_rules.WITNESS_ADDRESS_FIELD)}
    assert [strip(r) for r in rest] == [strip(r) for r in tf]


def test_a_counted_deny_block_refuses_unknown_multiplicity():
    doc = json.loads(json.dumps(PLAN))
    doc["planned_values"]["root_module"]["resources"][0]["values"]["count"] = 2
    records, missing, _ = deny_rows(doc, kind="tf_plan")
    assert records == ()
    assert "'count'" in missing and "instances" in missing


def test_a_deny_block_that_yielded_no_claims_aborts_by_census():
    """MK-D04's behaviour: a plan deny block whose rules are present but which
    the claim walker anchored nothing under is a policy whose rules were
    stripped or malformed — it must abstain naming the address, never go
    silent beside a healthy sibling."""
    doc = json.loads(json.dumps(PLAN))
    doc["planned_values"]["root_module"]["resources"][0]["values"]["rules"] = [
        "not-a-rule-object"]
    records, missing, _ = deny_rows(doc, kind="tf_plan")
    assert records == ()
    assert "google_iam_deny_policy.guardrail" in missing
    assert "yielded no readable claims" in missing


def test_a_plan_with_no_deny_resource_reports_the_missing_input():
    doc = {"format_version": "1.2",
           "planned_values": {"root_module": {"resources": [
               PLAN["planned_values"]["root_module"]["resources"][1]]}}}
    records, missing, _ = deny_rows(doc, kind="tf_plan")
    assert records == ()
    assert "carries no IAM deny policy resources" in missing


# -- the worked promises ---------------------------------------------------


def fld(name, var="r"):
    return {"node": "field", "var": var, "field": name}


def lit(sort, value):
    return {"node": "lit", "sort": sort, "value": value}


def cmp(op, left, right):
    return {"node": "cmp", "op": op, "left": left, "right": right}


#: "Every deny policy denies iam.serviceAccounts.getAccessToken with no
#: principal exceptions" — the STRONGEST judgeable spelling: everyone,
#: unconditionally, no carve-outs.
STRONG_AST = {"node": "exists", "var": "r", "collection": "deny_rules",
              "body": {"node": "and", "args": [
                  cmp("eq", fld("permission"), lit("Str", TOKEN)),
                  cmp("eq", fld("denied_principal"), lit("Str", PUBLIC_ALL)),
                  cmp("eq", fld("has_principal_exceptions"),
                      lit("Bool", False)),
                  cmp("eq", fld("has_condition"), lit("Bool", False)),
              ]}}

#: "No deny rule exempts the public" — refute mode over the second collection.
NO_PUBLIC_EXEMPTION_AST = {
    "node": "exists", "var": "e", "collection": "deny_rule_exceptions",
    "body": cmp("eq", fld("exception_principal", var="e"),
                lit("Str", PUBLIC_ALL))}


def promise(pid, mode, ast):
    """A compiled Promise the way tests/test_gcp_sec_domains.py builds one."""
    source = sec_artifact.Source(
        file="deny.md", line=3,
        text="every deny policy denies SA token minting for everyone")
    if HAVE_Z3:
        formula, consts = sec_encode.symbolic(Z3, ast)
        obl = sec_probes.obligation(Z3, formula, mode)
        positive, negative = sec_probes.mint(Z3, obl, consts)
        assert positive is not None and negative is not None
        sexpr = formula.sexpr()
    else:
        sexpr = "(assert true)"
        positive = negative = {"placeholder": "x"}
    return sec_artifact.Promise(
        id=pid, source=source, domain="iam", mode=mode, state="proposal",
        severity="high", vocabulary=(), ast=ast, sexpr=sexpr,
        free_consts=tuple(sec_ast.free_consts(ast)),
        positive=sec_artifact.Witness(assignment=positive, origin="z3-model"),
        negative=sec_artifact.Witness(assignment=negative, origin="z3-model"),
        wellformedness=sec_artifact.Wellformedness(satisfiable=True,
                                                   non_tautological=True),
        status="compiled", reason="")


def evaluate(mode, ast, document, kind="iam_deny_policy"):
    rule = sec_rules.CompiledRule(
        promise=promise("deny-sa-token-everyone", mode, ast))
    return rule.evaluate(ctx(document, kind))


def test_the_strong_promise_judges_the_four_rest_fixtures():
    strong = evaluate("assert_satisfiable", STRONG_AST, STRONG)
    threaded = evaluate("assert_satisfiable", STRONG_AST, THREADED)
    conditional = evaluate("assert_satisfiable", STRONG_AST, CONDITIONAL)
    malformed = evaluate("assert_satisfiable", STRONG_AST, MALFORMED)
    if not HAVE_Z3:
        for verdict in (strong, threaded, conditional):
            assert verdict.status == "unverified"
            assert "z3 is not available" in verdict.message
    else:
        assert strong.status == "grounded"
        # the carve-out (rule 0) and the clawed-back permission (rule 1) leave
        # no row satisfying the strong pattern
        assert threaded.status == "contradicted"
        # a maintenance-window denial is not an unconditional one
        assert conditional.status == "contradicted"
    # the malformed document abstains BEFORE any solve, so this arm is
    # backend-identical by construction
    assert malformed.status == "unverified"
    assert "rules[0]" in malformed.message


def test_the_strong_promise_abstains_off_kind_and_is_silent_off_domain():
    off_kind = evaluate("assert_satisfiable", STRONG_AST,
                        {"bindings": []}, kind="iam_policy")
    assert off_kind.status == "unverified"
    assert "not an IAM deny policy" in off_kind.message
    silent = evaluate("assert_satisfiable", STRONG_AST,
                      {"spec": {"rules": []}, "name": "x"}, kind="org_policy")
    assert silent is None  # an iam-domain promise says nothing about org kinds


def test_the_no_public_exemption_promise_rides_the_attestation():
    clean = evaluate("refute", NO_PUBLIC_EXEMPTION_AST, STRONG)
    threaded = evaluate("refute", NO_PUBLIC_EXEMPTION_AST, THREADED)
    exempting = json.loads(json.dumps(STRONG))
    # the rows keep the RAW v2 spelling, so the promise names the v2 public
    # set — the "allUsers" legacy spelling is a different raw string and a
    # promise about it is a second, separate promise
    exempting["rules"][0]["denyRule"]["exceptionPrincipals"] = [PUBLIC_ALL]
    nullified = evaluate("refute", NO_PUBLIC_EXEMPTION_AST, exempting)
    if not HAVE_Z3:
        assert {clean.status, threaded.status, nullified.status} == {"unverified"}
        return
    # an exception-free policy grounds WITH the observed-empty note — the
    # attestation never travels silently
    assert clean.status == "grounded"
    assert "none carries a principal exception" in clean.message
    assert threaded.status == "grounded"
    assert "none carries" not in threaded.message
    assert nullified.status == "contradicted"
    assert f"exception_principal='{PUBLIC_ALL}'" in nullified.message


def test_extraction_is_solver_free_and_identical_on_both_backends():
    """The deny extractors never touch a solver, so their records and reasons
    are byte-identical whichever backend decides the promise — asserted the
    way the iam_checks suites assert backend identity."""
    with_default = deny_rows(THREADED)
    builtin_ctx = sec_rules.RuleContext(snapshot=SNAP, document=THREADED,
                                        document_kind="iam_deny_policy",
                                        solver=get_solver(prefer="builtin"))
    with_builtin = sec_rules._normalize_extraction(
        "deny_rules", sec_rules.EXTRACTORS["deny_rules"](builtin_ctx))
    assert with_default == with_builtin
