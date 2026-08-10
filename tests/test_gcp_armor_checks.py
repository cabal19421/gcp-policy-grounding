"""Cloud Armor checks: the default rule, priority-order unreachability, the
priority bypass against both intra-policy and estate rules, and the curated
preconfigured-expression vocabulary.

Two polarities live in this module and reading either one backwards turns its
check into a no-op, so both are pinned in both directions:

* CHECK 2 (unreachable rule) is family (c) COVERAGE — ``And(match(r),
  Not(higher))`` **UNSAT** is the finding, SAT is healthy. The pin below asserts
  that a priority-2000 rule *inside* a priority-1000 rule is ``contradicted``
  AND that a priority-2000 rule *outside* it yields an empty list of
  ``armor_priority`` verdicts.
* CHECK 3 (priority bypass) is family (a) PROPOSAL — **SAT** is the finding and
  carries a witness.

CHECK 1 (the default rule) is pure structure: it counts rules and reads a
priority, so it must decide identically on the builtin backend. The
builtin-backend tests assert exactly that — a missing default is still
``contradicted`` and an allow-all default still carries its warning, while
CHECKS 2 and 3 abstain and CHECK 4 is unchanged.

:mod:`gcp_grounding.armor_expr` (the ``sx-armor-expr`` task) may not be part of
this worktree, so every expression-dependent assertion branches on
``HAVE_ARMOR_EXPR``: with the translator absent every expression rule and every
referenced expr id abstains, which is the same honest bucket the unsupported
path uses — never a ``contradicted``.
"""

import importlib.util
import ipaddress
import json
import re
from pathlib import Path

import pytest

from gcp_grounding import armor_checks, registry
from gcp_grounding.armor_claims import DEFAULT_RULE_PRIORITY, security_policy_claims
from gcp_grounding.armor_checks import check_security_policy
from gcp_grounding.claims import Claim
from gcp_grounding.core.report import GroundingReport
from gcp_grounding.core.solver import BuiltinSolver, get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import ground_policy
from gcp_grounding.registry import CheckContext

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

HAVE_Z3 = get_solver().backend == "z3"
needs_z3 = pytest.mark.skipif(not HAVE_Z3, reason="z3 solver backend is not available")

#: Whether the Armor match-expression translator landed in this checkout.
HAVE_ARMOR_EXPR = importlib.util.find_spec("gcp_grounding.armor_expr") is not None

SCANNERS = "203.0.113.0/24"
PARTNER = "198.51.100.0/24"


# -- fixtures and builders ---------------------------------------------------


@pytest.fixture()
def estate() -> GcpSnapshot:
    """The fully captured estate: ``cloud_armor_policies`` carries the deployed
    ``armor-policy-prod``, which denies 203.0.113.0/24 at priority 1000."""
    return GcpSnapshot.load(FIXTURES / "estate_snapshot.json")


@pytest.fixture()
def partial() -> GcpSnapshot:
    """Vocabularies captured, record tables absent — the abstention fixture."""
    return GcpSnapshot.load(FIXTURES / "estate_partial_snapshot.json")


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def config_rule(priority, action, ranges):
    return {"priority": priority, "action": action, "preview": False,
            "match": {"versionedExpr": "SRC_IPS_V1",
                      "config": {"srcIpRanges": list(ranges)}}}


def expr_rule(priority, action, expression):
    return {"priority": priority, "action": action, "preview": False,
            "match": {"expr": {"expression": expression}}}


DEFAULT_ALLOW = config_rule(DEFAULT_RULE_PRIORITY, "allow", ["*"])


def policy(name, rules):
    return {"name": name, "rules": rules}


def ctx_for(doc, snapshot, *, solver=None, source="policy.json"):
    """A :class:`CheckContext` over the claims *doc* makes, exactly as
    ``ground_policy`` would build it once ``detect_kind`` learns the
    ``security_policy`` kind (the ``sx-detect-kind`` task)."""
    return CheckContext(snapshot=snapshot, solver=solver or get_solver(),
                        document=doc, document_kind="security_policy", source=source,
                        claims=tuple(security_policy_claims(doc)))


def report_of(verdicts) -> GroundingReport:
    report = GroundingReport()
    for verdict in verdicts:
        report.add(verdict)
    return report


def of_kind(verdicts, kind):
    return [v for v in verdicts if v.kind == kind]


def witness_ip(message: str) -> str:
    match = re.search(r"source (\d+\.\d+\.\d+\.\d+)", message)
    assert match is not None, f"no witness source address in {message!r}"
    return match.group(1)


# -- registration ------------------------------------------------------------


def test_module_registers_exactly_the_document_check():
    assert armor_checks.DOCUMENT_CHECKS == (check_security_policy,)
    assert check_security_policy in registry.document_checks()


def test_a_document_without_armor_claims_is_silent(estate):
    ctx = CheckContext(snapshot=estate, solver=get_solver(), document={},
                       document_kind="iam_policy", source="iam.json",
                       claims=(Claim("role", "roles/viewer", "bindings[0].role"),))
    assert check_security_policy(ctx) == []


# -- CHECK 1: the default rule -----------------------------------------------


def test_fixture_policy_grounds_its_allow_all_default_with_the_warning(estate):
    verdicts = check_security_policy(ctx_for(load("armor_policy.json"), estate))
    [default] = of_kind(verdicts, "armor_default")
    assert (default.status, default.target) == ("grounded", "armor-policy-prod")
    assert ("default rule allows all traffic — this policy is a blocklist, "
            "not an allowlist") in default.message
    # …and the fixture policy is healthy: no dead rule, no bypass.
    assert of_kind(verdicts, "armor_priority") == []
    assert [v for v in verdicts if v.status == "contradicted"] == []
    assert report_of(verdicts).ok is True


def test_a_policy_with_no_default_rule_is_contradicted(estate):
    doc = policy("no-default", [config_rule(1000, "deny-403", [SCANNERS])])
    verdicts = check_security_policy(ctx_for(doc, estate))
    [default] = of_kind(verdicts, "armor_default")
    assert (default.status, default.target) == ("contradicted", "no-default")
    assert (f"the policy has no default rule at priority {DEFAULT_RULE_PRIORITY}"
            in default.message)
    assert report_of(verdicts).ok is False


def test_a_deny_default_is_a_plain_grounded_without_the_warning(estate):
    doc = policy("allowlist", [config_rule(1000, "allow", [PARTNER]),
                               config_rule(DEFAULT_RULE_PRIORITY, "deny-403", ["*"])])
    [default] = of_kind(check_security_policy(ctx_for(doc, estate)), "armor_default")
    assert default.status == "grounded"
    assert "blocklist" not in default.message


def test_a_standalone_rule_makes_no_claim_about_the_default(estate):
    # The tf fixture is one `google_compute_security_policy_rule`: it carries no
    # `policy_document` marker, so CHECK 1 must stay silent rather than read a
    # one-rule document as a policy missing its default.
    report = ground_policy(POLICIES / "armor_tf_plan.json", estate)
    assert of_kind(report.verdicts, "armor_default") == []


def test_an_unnormalizable_rule_abstains_instead_of_faking_a_missing_default(estate):
    # A rule whose action is outside the supported set normalizes to
    # {"unsupported": …} and loses its priority — including, possibly, the
    # default's. "No default rule" would then be a guess, not a finding.
    doc = policy("odd", [config_rule(1000, "quarantine", [SCANNERS])])
    [default] = of_kind(check_security_policy(ctx_for(doc, estate)), "armor_default")
    assert default.status == "unverified"
    assert "was not decided" in default.message


# -- CHECK 2: unreachable rules (family (c) COVERAGE) ------------------------


@needs_z3
def test_polarity_pin_a_rule_inside_a_lower_priority_rule_is_unreachable(estate):
    doc = policy("shadowed", [config_rule(1000, "deny-403", ["203.0.113.0/16"]),
                              config_rule(2000, "allow", [SCANNERS]),
                              DEFAULT_ALLOW])
    verdicts = check_security_policy(ctx_for(doc, estate))
    [dead] = of_kind(verdicts, "armor_priority")
    assert (dead.status, dead.target) == ("contradicted", "shadowed#2000")
    assert "rule at priority 2000 is unreachable" in dead.message
    assert "priority 1000" in dead.message
    assert report_of(verdicts).ok is False


@needs_z3
def test_polarity_pin_a_rule_outside_the_lower_priority_rule_is_live(estate):
    doc = policy("live", [config_rule(1000, "deny-403", ["203.0.113.0/16"]),
                          config_rule(2000, "allow", [PARTNER]),
                          DEFAULT_ALLOW])
    verdicts = check_security_policy(ctx_for(doc, estate))
    assert of_kind(verdicts, "armor_priority") == []
    assert report_of(verdicts).ok is True


@needs_z3
def test_the_default_rule_is_never_reported_unreachable(estate):
    # It matches everything at the lowest precedence by construction; a
    # preceding allow-all covers it entirely and that is not a finding.
    doc = policy("covered-default", [config_rule(1000, "allow", ["0.0.0.0/0"]),
                                     DEFAULT_ALLOW])
    verdicts = check_security_policy(ctx_for(doc, estate))
    assert of_kind(verdicts, "armor_priority") == []


@needs_z3
def test_a_rule_only_the_union_of_two_others_covers_names_them_together(estate):
    doc = policy("union", [config_rule(1000, "deny-403", ["203.0.113.0/25"]),
                           config_rule(1500, "deny-403", ["203.0.113.128/25"]),
                           config_rule(2000, "allow", [SCANNERS]),
                           DEFAULT_ALLOW])
    [dead] = of_kind(check_security_policy(ctx_for(doc, estate)), "armor_priority")
    assert dead.status == "contradicted"
    assert "priorities 1000, 1500 taken together" in dead.message


# -- CHECK 3: priority bypass (family (a) PROPOSAL) --------------------------


@needs_z3
def test_the_tf_allow_all_bypasses_the_estate_deny(estate):
    report = ground_policy(POLICIES / "armor_tf_plan.json", estate)
    [bypass] = of_kind(report.verdicts, "armor_bypass")
    assert bypass.status == "contradicted"
    assert "the allow at priority 1 bypasses the deny at priority 1000" in bypass.message
    assert "armor-policy-prod" in bypass.message
    assert (ipaddress.ip_address(witness_ip(bypass.message))
            in ipaddress.ip_network(SCANNERS))
    assert report.ok is False


@needs_z3
def test_an_intra_policy_allow_bypasses_a_later_deny(estate):
    doc = policy("intra", [config_rule(100, "allow", ["0.0.0.0/0"]),
                           config_rule(1000, "deny-403", [SCANNERS]),
                           DEFAULT_ALLOW])
    [bypass] = of_kind(check_security_policy(ctx_for(doc, estate)), "armor_bypass")
    assert bypass.status == "contradicted"
    assert "the allow at priority 100 bypasses the deny at priority 1000" in bypass.message
    assert (ipaddress.ip_address(witness_ip(bypass.message))
            in ipaddress.ip_network(SCANNERS))


@needs_z3
def test_an_allow_behind_the_deny_is_not_a_bypass(estate):
    # The deny has the SMALLER priority number, so it wins: nothing is bypassed
    # and the (disjoint-from-it) allow is still reachable.
    doc = policy("ordered", [config_rule(1000, "deny-403", [SCANNERS]),
                             config_rule(2000, "allow", [PARTNER]),
                             DEFAULT_ALLOW])
    verdicts = check_security_policy(ctx_for(doc, estate))
    assert of_kind(verdicts, "armor_bypass") == []
    assert report_of(verdicts).ok is True


@needs_z3
def test_an_estate_policy_that_is_absent_abstains(estate):
    # The ref resolves as a *name*, but no such policy was captured: the
    # bypass check against its rules was not made, and says so.
    doc = {"format_version": "1.2", "planned_values": {"root_module": {"resources": [{
        "address": "google_compute_security_policy_rule.r", "mode": "managed",
        "type": "google_compute_security_policy_rule", "name": "r",
        "provider_name": "registry.terraform.io/hashicorp/google",
        "values": {"priority": 1, "action": "allow", "preview": False,
                   "security_policy": "armor-policy-ghost",
                   "match": [{"config": [{"src_ip_ranges": ["0.0.0.0/0"]}]}]}}]}}}
    report = ground_policy(doc, estate)
    [abstain] = of_kind(report.verdicts, "armor_bypass")
    assert abstain.status == "unverified"
    assert "is not in the snapshot's captured cloud_armor_policies" in abstain.message


@needs_z3
def test_the_estate_bypass_path_abstains_on_the_partial_snapshot(partial):
    report = ground_policy(POLICIES / "armor_tf_plan.json", partial)
    [abstain] = of_kind(report.verdicts, "armor_bypass")
    assert abstain.status == "unverified"
    assert "cloud_armor_policies was not captured" in abstain.message
    # An uncaptured category never blocks: the whole report stays honest-green.
    assert report.ok is True


# -- unencodable rules: exactly one abstention, never a contradicted ---------


@needs_z3
def test_an_unsupported_match_expression_yields_one_unverified_for_that_rule(estate):
    doc = policy("expr-policy", [expr_rule(1000, "deny-403",
                                           "request.path.matches('/admin')"),
                                 DEFAULT_ALLOW])
    verdicts = check_security_policy(ctx_for(doc, estate))
    mine = [v for v in verdicts if v.target == "expr-policy#1000"]
    assert len(mine) == 1
    assert (mine[0].status, mine[0].kind) == ("unverified", "armor_rule")
    # The rest of the policy is still checked, and nothing is contradicted.
    assert of_kind(verdicts, "armor_default")[0].status == "grounded"
    assert [v for v in verdicts if v.status == "contradicted"] == []


# -- CHECK 4: the preconfigured-expression vocabulary ------------------------


def expr_id_claim(expr_id):
    """One rule claim carrying a referenced preconfigured expr id, shaped
    exactly as :func:`armor_claims.security_policy_claims` shapes it."""
    return Claim.of("security_policy_rule", "waf-policy", "rules[0]",
                    priority=1000, action="deny-403", preview=False,
                    match={"src_ip_ranges": [], "versioned_expr": None,
                           "expr": f"evaluatePreconfiguredWaf('{expr_id}')"},
                    referenced_expr_ids=[expr_id], policy="waf-policy",
                    rule_count=1, has_default=False)


def vocabulary_verdicts(expr_id, snapshot, *, solver=None):
    ctx = CheckContext(snapshot=snapshot, solver=solver or get_solver(),
                       document=None, document_kind="security_policy",
                       source="waf.json", claims=(expr_id_claim(expr_id),))
    return of_kind(check_security_policy(ctx), "armor_expr")


def test_an_unknown_preconfigured_expr_id_is_unverified_never_ungrounded(estate):
    [verdict] = vocabulary_verdicts("bogus-v42-stable", estate)
    assert (verdict.status, verdict.target) == ("unverified", "bogus-v42-stable")
    assert "is not in this build's curated list" in verdict.message
    assert "not decided" in verdict.message


def test_a_curated_expr_id_is_not_flagged(estate):
    verdicts = vocabulary_verdicts("sqli-v33-stable", estate)
    if HAVE_ARMOR_EXPR:
        assert verdicts == []
    else:
        # No curated list in this checkout: every id is merely unverified,
        # which is the same honest bucket — never ungrounded.
        assert [v.status for v in verdicts] == ["unverified"]


# -- the builtin backend: CHECK 1 still decides ------------------------------


def builtin_ctx(doc, snapshot):
    return ctx_for(doc, snapshot, solver=BuiltinSolver())


def test_builtin_backend_still_contradicts_a_missing_default(estate):
    doc = policy("no-default", [config_rule(1000, "deny-403", [SCANNERS])])
    verdicts = check_security_policy(builtin_ctx(doc, estate))
    [default] = of_kind(verdicts, "armor_default")
    assert default.status == "contradicted"
    assert report_of(verdicts).ok is False


def test_builtin_backend_keeps_the_allow_all_default_warning_and_passes(estate):
    verdicts = check_security_policy(builtin_ctx(load("armor_policy.json"), estate))
    [default] = of_kind(verdicts, "armor_default")
    assert default.status == "grounded"
    assert ("default rule allows all traffic — this policy is a blocklist, "
            "not an allowlist") in default.message
    assert report_of(verdicts).ok is True


def test_builtin_backend_abstains_from_checks_2_and_3(estate):
    doc = policy("shadowed", [config_rule(1000, "deny-403", ["203.0.113.0/16"]),
                              config_rule(2000, "allow", [SCANNERS]),
                              DEFAULT_ALLOW])
    verdicts = check_security_policy(builtin_ctx(doc, estate))
    [abstain] = of_kind(verdicts, "armor_rule")
    assert abstain.status == "unverified"
    assert "z3 is not available" in abstain.message
    # The dead rule z3 would have found is NOT reported — abstain, never guess.
    assert of_kind(verdicts, "armor_priority") == []
    assert of_kind(verdicts, "armor_bypass") == []
    assert report_of(verdicts).ok is True


def test_builtin_backend_leaves_check_4_unchanged(estate):
    def rendered(solver):
        return [(v.status, v.kind, v.target, v.message)
                for v in vocabulary_verdicts("bogus-v42-stable", estate, solver=solver)]

    assert rendered(BuiltinSolver()) == rendered(get_solver())
    assert [row[0] for row in rendered(BuiltinSolver())] == ["unverified"]
