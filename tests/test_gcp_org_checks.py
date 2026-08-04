"""Org Policy enforcement / list-value grounding — the sixth domain arm.

The gap this suite closes: ``enforce: true`` and ``enforce: false`` used to
produce BYTE-IDENTICAL grounding reports, both passing, because the only
org-policy claim carrying value information recorded the value *type* and never
the value. Every test here is against the shared estate fixtures — the full
``estate_snapshot.json`` for the decisions, its record-table-less twin
``estate_partial_snapshot.json`` for the abstentions.

Two properties are asserted throughout rather than in one place. First,
**abstention**: an uncaptured ``org_policies`` table and a node that table does
not record each yield exactly one ``unverified`` and never a ``contradicted``.
Second, **backend independence**: the module is set algebra and a boolean
comparison with no z3 anywhere, so the whole file runs twice — once on whatever
backend is installed, once with :func:`get_solver` forced to ``"builtin"`` —
and every assertion must hold identically in both.
"""

import ast
import copy
import json
from pathlib import Path

import pytest

from gcp_grounding import org_checks, preflight, registry
from gcp_grounding.claims import Claim, org_policy_claims
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.org_checks import (CLAIM_CHECKS, DOCUMENT_CHECKS,
                                      check_constraint_enforcement,
                                      check_org_estate, hierarchy_value_claims)
from gcp_grounding.preflight import detect_kind, ground_policy
from gcp_grounding.registry import CheckContext
from tests.lineno_invariant import assert_no_line_numbers

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

SERIAL = "constraints/compute.disableSerialPortAccess"
DOMAINS = "constraints/iam.allowedPolicyMemberDomains"
EXTERNAL_IP = "constraints/compute.vmExternalIpAccess"
KEYS = "constraints/iam.disableServiceAccountKeyCreation"
NODE = "projects/acme-prod"


@pytest.fixture(params=["installed", "builtin"], autouse=True)
def backend(request, monkeypatch):
    """Run every test twice: as shipped, and with the builtin solver forced.

    ``org_checks`` never touches ``ctx.solver``; forcing the stdlib backend
    must therefore change nothing at all about its verdicts.
    """
    if request.param == "builtin":
        monkeypatch.setattr(preflight, "get_solver",
                            lambda *a, **k: get_solver(prefer="builtin"))
    return request.param


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "estate_snapshot.json")


@pytest.fixture()
def partial() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "estate_partial_snapshot.json")


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def enforcement(report) -> list:
    return [v for v in report.verdicts if v.kind == org_checks.VERDICT_KIND]


def context(snapshot, document, claims=(), baseline=None, baseline_kind=None,
            solver=None) -> CheckContext:
    """A CheckContext exactly as ``ground_policy`` builds one. ``solver=None``
    is deliberate: nothing in this module may read it."""
    return CheckContext(snapshot=snapshot, solver=solver, document=document,
                        document_kind="org_policy", source="<policy object>",
                        claims=tuple(claims), baseline=baseline,
                        baseline_kind=baseline_kind)


def with_org_policy(snapshot: GcpSnapshot, node: str, constraint: str,
                    rules: list, **flags) -> GcpSnapshot:
    """*snapshot* with one extra recorded org policy — the estate fixture is
    byte-pinned elsewhere, so a case it does not cover is built here."""
    record = {"node": node, "constraint": constraint, "reset": False,
              "inherit_from_parent": False, "rules": rules, **flags}
    policies = dict(snapshot.to_dict().get("org_policies") or {})
    policies[f"{node}|{constraint}"] = record
    return GcpSnapshot.from_dict(dict(snapshot.to_dict(), org_policies=policies))


def rule(**fields) -> dict:
    """One estate rule record, in the snapshot's normalized spelling."""
    return {"enforce": None, "allow_all": None, "deny_all": None,
            "allowed_values": [], "denied_values": [], **fields}


def enforcement_claim(document) -> Claim:
    [claim] = [c for c in org_policy_claims(document)
               if c.kind == "constraint_enforcement"]
    return claim


# -- registration -------------------------------------------------------------


def test_module_is_registered_as_the_design_specifies():
    assert CLAIM_CHECKS == {"constraint_enforcement": check_constraint_enforcement}
    assert DOCUMENT_CHECKS == (check_org_estate,)
    assert "gcp_grounding.org_checks" in registry.PROVIDER_MODULES
    registry.reset_cache()
    assert check_constraint_enforcement in registry.claim_checks("constraint_enforcement")
    assert check_org_estate in registry.document_checks()


def test_no_z3_anywhere_in_the_module():
    # Set algebra and a boolean comparison: the decisions must not depend on a
    # solver being importable, so the module must not reach for one at all.
    tree = ast.parse(Path(org_checks.__file__).read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, ast.Import) for alias in node.names}
    imported |= {(node.module or "").split(".")[0] for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom)}
    assert "z3" not in imported
    assert not [n for n in ast.walk(tree)
                if isinstance(n, ast.Attribute) and n.attr == "solver"]


# -- the headline: enforcement removal ---------------------------------------


def test_disabled_org_policy_is_contradicted_naming_constraint_and_node(snap):
    report = ground_policy(POLICIES / "org_policy_disabled.json", snap)
    assert not report.ok
    [finding] = report.contradicted
    assert (finding.status, finding.kind) == ("contradicted", "org_enforcement")
    assert finding.target == SERIAL
    assert SERIAL in finding.message and NODE in finding.message
    assert "enforce is false" in finding.message
    assert "guardrail" in finding.message


def test_enforcing_the_same_policy_grounds_and_the_reports_differ(snap):
    disabled = load("org_policy_disabled.json")
    enabled = copy.deepcopy(disabled)
    enabled["spec"]["rules"][0]["enforce"] = True

    off = ground_policy(disabled, snap)
    on = ground_policy(enabled, snap)

    assert not off.ok
    assert on.ok
    [kept] = enforcement(on)
    assert kept.status == "grounded"
    assert SERIAL in kept.message and NODE in kept.message
    # THE regression this arm exists to close: the two reports were once
    # byte-identical, so flipping the flag off was invisible to the gate.
    assert json.dumps(off.to_dict(), sort_keys=True) != \
        json.dumps(on.to_dict(), sort_keys=True)
    assert off.render() != on.render()


@pytest.mark.parametrize("spec, spelling", [
    ({"reset": True}, "spec.reset"),
    ({"inheritFromParent": True}, "spec.inheritFromParent"),
    ({"inherit_from_parent": True}, "spec.inheritFromParent"),
])
def test_the_other_two_disablement_spellings_fire_the_same_finding(snap, spec, spelling):
    # A check that caught only `enforce: false` would be evaded by these.
    document = {"name": f"{NODE}/policies/compute.disableSerialPortAccess",
                "spec": dict(spec, etag="CO3B0aQGEKDkxwU=")}
    report = ground_policy(document, snap)
    assert not report.ok
    [finding] = report.contradicted
    assert (finding.kind, finding.target) == ("org_enforcement", SERIAL)
    assert NODE in finding.message and spelling in finding.message
    assert "stops enforcing" in finding.message


@pytest.mark.parametrize("proposed, detail", [
    (True, "enforce is true"),
    (False, "not enforced here before"),
])
def test_enforcing_or_leaving_off_what_was_never_enforced_grounds(snap, proposed, detail):
    # An estate record that exists but does not enforce: turning enforcement
    # ON removes no guardrail, and leaving it off removes none either.
    off = with_org_policy(snap, NODE, KEYS, [rule(enforce=False)])
    document = {"name": f"{NODE}/policies/iam.disableServiceAccountKeyCreation",
                "spec": {"rules": [{"enforce": proposed}]}}
    report = ground_policy(document, off)
    assert report.ok
    [verdict] = enforcement(report)
    assert verdict.status == "grounded"
    assert detail in verdict.message
    assert KEYS in verdict.message and NODE in verdict.message


def test_a_prior_reset_record_does_not_count_as_enforcing(snap):
    # The record carries enforce: true but is itself a reset, so it enforced
    # nothing — turning it off cannot remove a guardrail.
    was_reset = with_org_policy(snap, NODE, KEYS, [rule(enforce=True)], reset=True)
    document = {"name": f"{NODE}/policies/iam.disableServiceAccountKeyCreation",
                "spec": {"rules": [{"enforce": False}]}}
    report = ground_policy(document, was_reset)
    assert report.ok
    assert [v.status for v in enforcement(report)] == ["grounded"]


# -- list widening ------------------------------------------------------------


def test_widened_list_is_contradicted_naming_the_added_value(snap):
    report = ground_policy(POLICIES / "org_policy_widened.json", snap)
    assert not report.ok
    [finding] = report.contradicted
    assert (finding.kind, finding.target) == ("org_enforcement", DOMAINS)
    assert "evil.example" in finding.message
    assert "widened" in finding.message and NODE in finding.message


def test_narrowing_the_same_list_grounds(snap):
    narrowed = load("org_policy_widened.json")
    narrowed["spec"]["rules"][0]["values"] = {
        "allowedValues": ["C01abcdef"], "deniedValues": ["evil.example"]}
    report = ground_policy(narrowed, snap)
    assert report.ok
    statuses = {v.status for v in enforcement(report)}
    assert statuses == {"grounded"}
    [widening] = [v for v in enforcement(report) if "allowed values" in v.message]
    assert "narrows or leaves them" in widening.message


def test_removing_an_allowed_value_grounds(snap):
    document = {"name": f"{NODE}/policies/iam.allowedPolicyMemberDomains",
                "spec": {"rules": [{"values": {"deniedValues": ["evil.example"]}}]}}
    report = ground_policy(document, snap)
    assert report.ok


def test_allow_all_over_an_enumerated_allowlist_is_the_maximal_widening(snap):
    document = {"name": f"{NODE}/policies/iam.allowedPolicyMemberDomains",
                "spec": {"rules": [{"allowAll": True}]}}
    report = ground_policy(document, snap)
    assert not report.ok
    [finding] = report.contradicted
    assert finding.status == "contradicted" and finding.target == DOMAINS
    assert "allows ALL values" in finding.message
    assert "C01abcdef" in finding.message and "maximal widening" in finding.message


def test_nothing_can_widen_a_record_that_already_allows_everything(snap):
    prior = {"constraint": DOMAINS, "node": NODE, "reset": False,
             "inherit_from_parent": False,
             "rules": [{"enforce": None, "allow_all": True, "deny_all": None,
                        "allowed_values": [], "denied_values": []}]}
    wide = GcpSnapshot.from_dict(dict(snap.to_dict(),
                                      org_policies={f"{NODE}|{DOMAINS}": prior}))
    report = ground_policy(load("org_policy_widened.json"), wide)
    assert report.ok
    [verdict] = [v for v in enforcement(report) if "already allows every value"
                 in v.message]
    assert verdict.status == "grounded"


# -- abstention: uncaptured table, unrecorded node ---------------------------


@pytest.mark.parametrize("name", ["org_policy_disabled.json", "org_policy_widened.json",
                                  "org_policy_good.json", "org_policy_bad.json"])
def test_partial_estate_yields_exactly_one_unverified_and_never_contradicts(
        partial, name):
    report = ground_policy(POLICIES / name, partial)
    findings = enforcement(report)
    assert [v.status for v in findings] == ["unverified"]
    assert "were not captured" in findings[0].message
    assert not [v for v in report.contradicted if v.kind == "org_enforcement"]


def test_node_absent_from_a_captured_table_is_unverified_naming_the_node(snap):
    # org_policy_good is set at the ORGANIZATION; the captured table records
    # only project-level policies. "Not recorded" is not "not enforced".
    report = ground_policy(POLICIES / "org_policy_good.json", snap)
    assert report.ok  # unverified never fails the gate
    [verdict] = enforcement(report)
    assert verdict.status == "unverified"
    assert "organizations/123456789012" in verdict.message
    assert "unrecorded node is not an unenforced one" in verdict.message


def test_a_v1_document_names_no_node_and_abstains(snap):
    report = ground_policy({"constraint": SERIAL, "booleanPolicy": {"enforced": False}},
                           snap)
    [verdict] = enforcement(report)
    assert verdict.status == "unverified"
    assert "does not name the node" in verdict.message
    assert not report.contradicted


# -- the baseline is better evidence than the snapshot -----------------------


def test_baseline_rules_are_preferred_over_the_snapshot_record(snap):
    name = f"{NODE}/policies/iam.disableServiceAccountKeyCreation"
    baseline = {"name": name, "spec": {"rules": [{"enforce": True}]}}
    document = {"name": name, "spec": {"rules": [{"enforce": False}]}}
    # The estate records nothing for this node/constraint pair, so without the
    # baseline the change is honestly undecided; the PAIR decides it.
    alone = ground_policy(document, snap)
    assert alone.ok and [v.status for v in enforcement(alone)] == ["unverified"]
    report = ground_policy(document, snap, baseline=baseline)
    [finding] = [v for v in report.contradicted if v.kind == "org_enforcement"]
    assert "the baseline document" in finding.message
    assert KEYS in finding.message


def test_a_baseline_overrides_a_snapshot_that_disagrees_with_it(snap):
    # The estate says serial-port access is enforced; the baseline PAIR says it
    # was already off. The better evidence wins, and the message says which.
    name = f"{NODE}/policies/compute.disableSerialPortAccess"
    baseline = {"name": name, "spec": {"rules": [{"enforce": False}]}}
    report = ground_policy(load("org_policy_disabled.json"), snap, baseline=baseline)
    assert report.ok
    [verdict] = enforcement(report)
    assert verdict.status == "grounded"
    assert "the baseline document" in verdict.message


def test_the_snapshot_source_is_named_when_no_baseline_is_used(snap):
    report = ground_policy(POLICIES / "org_policy_disabled.json", snap)
    [finding] = report.contradicted
    assert f"the estate snapshot captured {snap.captured_at}" in finding.message


def test_a_baseline_about_another_constraint_falls_back_to_the_snapshot(snap):
    baseline = {"name": f"{NODE}/policies/iam.allowedPolicyMemberDomains",
                "spec": {"rules": [{"values": {"allowedValues": ["C01abcdef"]}}]}}
    report = ground_policy(load("org_policy_disabled.json"), snap, baseline=baseline)
    [finding] = [v for v in report.contradicted if v.kind == "org_enforcement"]
    assert "the estate snapshot captured" in finding.message


# -- the payload: the values travel ------------------------------------------


def test_constraint_enforcement_payload_round_trips_through_fields():
    claim = enforcement_claim({
        "name": f"{NODE}/policies/iam.allowedPolicyMemberDomains",
        "spec": {"inheritFromParent": True, "reset": False,
                 "rules": [{"values": {"allowedValues": ["C01abcdef", "acme.example"],
                                       "deniedValues": ["evil.example"]}}]}})
    assert claim.kind == "constraint_enforcement"
    assert claim.value == DOMAINS
    assert claim.location == "spec.rules[0]"
    assert claim.fields() == {
        "node": NODE,
        "rule_index": 0,
        "enforce": None,
        "allow_all": None,
        "deny_all": None,
        "allowed_values": ["C01abcdef", "acme.example"],
        "denied_values": ["evil.example"],
        "reset": False,
        "inherit_from_parent": True,
    }
    # Frozen, so two extractions of the same document are equal and hashable.
    twin = enforcement_claim(copy.deepcopy(load("org_policy_widened.json")))
    assert twin == enforcement_claim(load("org_policy_widened.json"))
    assert len({twin, enforcement_claim(load("org_policy_widened.json"))}) == 1
    assert twin.fields()["allowed_values"] == ["C01abcdef", "evil.example"]


def test_boolean_and_list_v1_documents_map_onto_the_same_payload():
    boolean = enforcement_claim({"constraint": SERIAL,
                                 "booleanPolicy": {"enforced": True}})
    assert boolean.fields()["enforce"] is True
    assert boolean.fields()["node"] == ""
    listed = enforcement_claim({"constraint": EXTERNAL_IP,
                                "listPolicy": {"allValues": "ALLOW",
                                               "inheritFromParent": True}})
    assert listed.fields()["allow_all"] is True
    assert listed.fields()["inherit_from_parent"] is True
    restored = enforcement_claim({"constraint": SERIAL, "booleanPolicy": {},
                                  "restoreDefault": {}})
    assert restored.fields()["reset"] is True


def test_an_ambiguous_or_shapeless_rule_emits_no_enforcement_claim():
    # Two value-type keys at once: the pre-existing extractor already refuses
    # to guess, and the new claim must not guess either.
    ambiguous = {"name": f"{NODE}/policies/compute.disableSerialPortAccess",
                 "spec": {"rules": [{"enforce": True, "values": {}}]}}
    assert [c.kind for c in org_policy_claims(ambiguous)] == ["constraint"]
    # Neither shape at all.
    assert [c.kind for c in org_policy_claims(
        {"name": f"{NODE}/policies/compute.disableSerialPortAccess",
         "spec": {"rules": [{"condition": {"expression": "true"}}]}})] == ["constraint"]
    # A constraint the document does not name unambiguously: nothing at all.
    assert org_policy_claims({"constraint": SERIAL, "name": "x/policies/y"}) == []


# -- CHECK 3: hierarchy-node values ------------------------------------------


def test_a_hierarchy_node_value_emits_a_hierarchy_node_ref_claim(snap):
    claim = enforcement_claim({
        "name": f"{NODE}/policies/compute.vmExternalIpAccess",
        "spec": {"rules": [{"values": {"allowedValues": [NODE, "folders/2"],
                                       "deniedValues": ["organizations/1"]}}]}})
    emitted = hierarchy_value_claims(claim)
    assert [(c.kind, c.value) for c in emitted] == [
        ("hierarchy_node_ref", NODE),
        ("hierarchy_node_ref", "folders/2"),
        ("hierarchy_node_ref", "organizations/1"),
    ]
    assert emitted[0].location == "spec.rules[0].values.allowedValues[0]"
    verdicts = check_org_estate(context(snap, {}, claims=[claim]))
    assert [(v.status, v.kind) for v in verdicts] == [("grounded", "hierarchy_node")] * 3


def test_a_customer_id_and_an_instance_path_emit_no_existence_claim(snap):
    # Customer ids are not groundable offline; an instance path carries a
    # `projects/` prefix but is not a node — guessing either would manufacture
    # a false `ungrounded`.
    opaque = enforcement_claim(load("org_policy_widened.json"))
    assert hierarchy_value_claims(opaque) == []
    instance = enforcement_claim({
        "name": f"{NODE}/policies/compute.vmExternalIpAccess",
        "spec": {"rules": [{"values": {"deniedValues": [
            f"{NODE}/zones/us-central1-a/instances/legacy-box"]}}]}})
    assert hierarchy_value_claims(instance) == []
    assert check_org_estate(context(snap, {}, claims=[opaque, instance])) == []


def test_a_hallucinated_node_value_is_ungrounded_with_a_suggestion(snap):
    document = {"name": f"{NODE}/policies/compute.vmExternalIpAccess",
                "spec": {"rules": [{"values": {"allowedValues": ["projects/acme-prd"]}}]}}
    report = ground_policy(document, snap)
    [missing] = [v for v in report.ungrounded if v.kind == "hierarchy_node"]
    assert missing.target == "projects/acme-prd"
    assert NODE in missing.suggestions
    assert not report.ok


def test_a_v1_list_policy_points_at_its_own_value_path():
    claim = enforcement_claim({"constraint": EXTERNAL_IP,
                               "listPolicy": {"allowedValues": ["folders/2"]}})
    [emitted] = hierarchy_value_claims(claim)
    assert emitted.location == "listPolicy.allowedValues[0]"


def test_check_org_estate_is_silent_on_documents_with_no_org_claims(snap):
    assert check_org_estate(context(snap, {}, claims=())) == []
    assert check_org_estate(context(
        snap, {}, claims=[Claim("role", "roles/viewer", "bindings[0].role")])) == []


# -- the pre-existing verdicts are untouched ---------------------------------


def test_pre_existing_org_policy_verdicts_are_unchanged():
    # The exact expectations of tests/test_gcp_preflight.py, re-asserted here
    # against the vocabulary-only snapshot those tests use: the new claim adds
    # a verdict, it never alters or removes one.
    vocab = GcpSnapshot.load(FIXTURES / "snapshot.json")
    good = ground_policy(POLICIES / "org_policy_good.json", vocab)
    assert good.ok
    assert [(v.status, v.kind) for v in good.verdicts if v.kind != "org_enforcement"] \
        == [("grounded", "constraint"), ("grounded", "constraint")]
    bad = ground_policy(POLICIES / "org_policy_bad.json", vocab)
    assert not bad.ok
    assert [(v.status, v.kind) for v in bad.verdicts if v.kind != "org_enforcement"] \
        == [("grounded", "constraint"), ("contradicted", "constraint")]
    [mismatch] = bad.contradicted
    assert "boolean" in mismatch.message
    # Both bundles are still org_policy documents through the `/policies/` arm.
    for name in ("org_policy_good.json", "org_policy_bad.json",
                 "org_policy_disabled.json", "org_policy_widened.json"):
        assert detect_kind(load(name)) == "org_policy"


def test_every_claim_still_receives_at_least_one_verdict(snap):
    for name in ("org_policy_disabled.json", "org_policy_widened.json",
                 "org_policy_good.json", "org_policy_bad.json"):
        document = load(name)
        report = ground_policy(document, snap)
        assert len(report.verdicts) >= len(org_policy_claims(document))
        assert not [v for v in report.verdicts
                    if "no offline check is wired" in v.message]


# -- backend independence, asserted directly ---------------------------------


@pytest.mark.parametrize("name", ["org_policy_disabled.json", "org_policy_widened.json",
                                  "org_policy_good.json", "org_policy_bad.json"])
def test_the_builtin_backend_decides_identically(snap, name):
    # Beyond the file-wide double run: the same claims, checked against a
    # context carrying each backend in turn, must yield identical verdicts.
    document = load(name)
    claims = org_policy_claims(document)

    def decide(solver):
        ctx = context(snap, document, claims, solver=solver)
        verdicts = [v for c in claims if c.kind == "constraint_enforcement"
                    for v in check_constraint_enforcement(c, ctx)]
        return [(v.status, v.kind, v.target, v.message)
                for v in verdicts + check_org_estate(ctx)]

    assert decide(get_solver(prefer="builtin")) == decide(get_solver())
    assert decide(get_solver(prefer="builtin")) == decide(None)


def test_the_check_never_reads_the_solver(snap):
    # ctx.solver is None here: a solver-free check must decide anyway.
    document = load("org_policy_disabled.json")
    claim = enforcement_claim(document)
    [verdict] = check_constraint_enforcement(claim, context(snap, document, [claim]))
    assert verdict.status == "contradicted"


def test_a_non_enforcement_claim_is_rejected(snap):
    with pytest.raises(ValueError):
        check_constraint_enforcement(
            Claim("role", "roles/viewer", "bindings[0].role"), context(snap, {}))


# -- the shared lineno invariant ----------------------------------------------


def test_no_org_verdict_carries_a_line_number(snap, partial):
    """Every arm of this module reports ``lineno`` 0 — see lineno_invariant.

    Drives the committed org documents over both estate snapshots, each as
    another's ``--baseline``, and over the priors CHECK 2 needs, built with
    ``with_org_policy``. Two arms carry no committed document of their own —
    a proposal naming no node, one setting ``allowAll`` — so each is driven
    from a committed fixture with that one field changed.
    """
    docs = [load(n) for n in ("org_policy_good.json", "org_policy_bad.json",
                              "org_policy_disabled.json",
                              "org_policy_widened.json")]
    unnamed = {k: v for k, v in docs[3].items() if k != "name"}
    unnamed["constraint"] = DOMAINS
    allow_all = copy.deepcopy(docs[3])
    allow_all["spec"]["rules"] = [{"allowAll": True}]
    narrow = with_org_policy(snap, NODE, DOMAINS, [rule(allowed_values=["C01abcdef"])])
    wide = with_org_policy(snap, NODE, DOMAINS, [rule(allow_all=True)])
    enforcing = with_org_policy(snap, NODE, DOMAINS, [rule(enforce=True)])

    reports = [ground_policy(d, s) for d in docs for s in (snap, partial)]
    reports += [ground_policy(d, snap, baseline=b) for d in docs for b in docs]
    reports += [ground_policy(docs[3], s) for s in (narrow, wide, enforcing)]
    reports += [ground_policy(d, s) for d in (unnamed, allow_all)
                for s in (narrow, snap)]

    # Non-vacuity: the drive really decides, in all three directions.
    assert {v.status for r in reports for v in enforcement(r)} == {
        "unverified", "grounded", "contradicted"}
    for report in reports:
        assert_no_line_numbers(report)
