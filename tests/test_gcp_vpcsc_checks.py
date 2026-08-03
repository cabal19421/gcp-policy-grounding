"""VPC Service Controls check tests: protection removal and ingress/egress widening.

Pins the honesty contract of :mod:`gcp_grounding.vpcsc_checks`:

- the old perimeter comes from the ``--baseline`` document when one was given
  and from the snapshot otherwise, and when *neither* is available the check
  says the previous state is unknown instead of guessing;
- protection removal (projects, restricted services, a REGULAR→BRIDGE demotion)
  is plain set algebra, so it decides on the builtin backend too, while the
  widening comparison needs z3 and abstains without it;
- a dry-run-only proposal is compared against ``spec``, never ``status``, so it
  neither fabricates a removal nor hides one;
- an old *empty* policy list and an old *absent* policy key are different
  claims about the world: the first makes any new policy a widening, the second
  is undecidable offline and abstains.

Environment-honest like ``test_gcp_preflight``: every expectation that needs the
solver branches on whether z3 is importable.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding import registry
from gcp_grounding.core.solver import BuiltinSolver, get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import detect_kind, ground_policy
from gcp_grounding.registry import CheckContext
from gcp_grounding.vpcsc_checks import (
    DOCUMENT_CHECKS, PAIR_CHECKS, check_perimeter_estate, check_perimeter_pair,
)
from gcp_grounding.vpcsc_claims import perimeter_claims

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

HAVE_Z3 = get_solver().backend == "z3"

NAME = "accessPolicies/987/servicePerimeters/prod"
REMOVED_PROJECT = "projects/123456"
REMOVED_SERVICE = "bigquery.googleapis.com"


@pytest.fixture(autouse=True)
def _clean_registry():
    """Discover the real provider modules — this task's included — fresh for
    every test, and never leak a warm cache into the next."""
    registry.reset_cache()
    yield
    registry.reset_cache()


@pytest.fixture()
def estate() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "estate_snapshot.json")


@pytest.fixture()
def partial() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "estate_partial_snapshot.json")


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def vpcsc(report) -> list:
    """Only the verdicts this module owns — the same report also carries the
    existence pass's verdicts for the perimeter's resources and access levels."""
    return [v for v in report.verdicts if v.kind.startswith("vpcsc_")]


def triples(verdicts) -> list:
    return sorted((v.status, v.kind, v.target) for v in verdicts)


def messages(verdicts, status: str, kind: str) -> str:
    return "\n".join(v.message for v in verdicts
                     if v.status == status and v.kind == kind)


# -- CHECK 1 + CHECK 2 through the PAIR path ----------------------------------


def test_shrunk_against_its_baseline_is_contradicted(estate):
    report = ground_policy(POLICIES / "vpcsc_perimeter_shrunk.json", estate,
                           baseline=POLICIES / "vpcsc_perimeter.json")
    found = vpcsc(report)

    removal = messages(found, "contradicted", "vpcsc_protection")
    assert REMOVED_PROJECT in removal and "lose VPC-SC protection" in removal
    assert REMOVED_SERVICE in removal
    assert ("contradicted", "vpcsc_protection", NAME) in triples(found)
    assert not report.ok

    if HAVE_Z3:
        # ANY_IDENTITY left the identity axis free, so the witness identity is
        # *any* identity — the new policy lets every one of them out.
        widening = messages(found, "contradicted", "vpcsc_egress")
        assert "newly permits <any identity>" in widening
        assert "storage.googleapis.com.google.storage.objects.get" in widening
    else:
        assert ("unverified", "vpcsc_egress", NAME) in triples(found)


def test_reverse_pairing_is_grounded_on_both(estate):
    report = ground_policy(POLICIES / "vpcsc_perimeter.json", estate,
                           baseline=POLICIES / "vpcsc_perimeter_shrunk.json")
    got = triples(vpcsc(report))

    assert ("grounded", "vpcsc_protection", NAME) in got
    assert ("grounded" if HAVE_Z3 else "unverified", "vpcsc_egress", NAME) in got
    assert not [v for v in vpcsc(report) if v.status == "contradicted"]


def test_pair_path_reports_no_ingress_widening_when_none_is_proposed(estate):
    # allowed(new) is BoolVal(False) for an empty policy list, so this decides
    # without the solver — and must never be mistaken for an abstention.
    report = ground_policy(POLICIES / "vpcsc_perimeter_shrunk.json", estate,
                           baseline=POLICIES / "vpcsc_perimeter.json")
    assert ("grounded", "vpcsc_ingress", NAME) in triples(vpcsc(report))


# -- the ESTATE path (no baseline) --------------------------------------------


def test_estate_path_finds_the_same_removal(estate):
    pair = ground_policy(POLICIES / "vpcsc_perimeter_shrunk.json", estate,
                         baseline=POLICIES / "vpcsc_perimeter.json")
    solo = ground_policy(POLICIES / "vpcsc_perimeter_shrunk.json", estate)

    def bad(report):
        return triples(v for v in vpcsc(report) if v.status == "contradicted")

    assert bad(solo) == bad(pair)
    removal = messages(vpcsc(solo), "contradicted", "vpcsc_protection")
    assert REMOVED_PROJECT in removal and REMOVED_SERVICE in removal
    assert not solo.ok


def test_estate_path_abstains_when_the_category_was_not_captured(partial):
    report = ground_policy(POLICIES / "vpcsc_perimeter_shrunk.json", partial)
    found = vpcsc(report)

    # Exactly one verdict, and it is an abstention naming the ignorance: with
    # no baseline and no captured perimeter table there is no "previous state"
    # to compare against, and neither check may guess one.
    assert len(found) == 1
    verdict = found[0]
    assert (verdict.status, verdict.kind, verdict.target) == (
        "unverified", "vpcsc_protection", NAME)
    assert "previous state" in verdict.message
    assert "protection removal was not decided" in verdict.message


def test_estate_path_abstains_when_the_perimeter_is_absent(estate):
    doc = load("vpcsc_perimeter_shrunk.json")
    doc["name"] = "accessPolicies/987/servicePerimeters/staging"
    report = ground_policy(doc, estate)
    found = vpcsc(report)

    assert len(found) == 1
    assert (found[0].status, found[0].kind) == ("unverified", "vpcsc_protection")
    assert "is not in the snapshot" in found[0].message


# -- dry-run honesty ----------------------------------------------------------


def test_dry_run_only_change_is_grounded_and_never_compared_to_status(estate):
    # The proposal's `spec` drops bigquery relative to the baseline's *status*;
    # comparing the two would mint a false `contradicted`, because a dry-run
    # spec enforces nothing.
    report = ground_policy(POLICIES / "vpcsc_perimeter_dry_run.json", estate,
                           baseline=POLICIES / "vpcsc_perimeter.json")
    found = vpcsc(report)
    got = triples(found)

    assert ("grounded", "vpcsc_dry_run", NAME) in got
    assert messages(found, "grounded", "vpcsc_dry_run").count(
        "dry-run only — this change does not alter enforcement") == 1
    assert not [v for v in found if v.status == "contradicted"]
    # Check 1 still ran — against `spec` — and says so.
    protection = messages(found, "grounded", "vpcsc_protection")
    assert "removes nothing" in protection
    assert "dry-run only — this change does not alter enforcement" in protection


def test_dry_run_against_an_estate_record_without_a_spec_abstains(estate):
    # The captured perimeter has `spec: null`, so there is no previous dry-run
    # spec to diff — and `status` is the wrong thing to diff it against.
    report = ground_policy(POLICIES / "vpcsc_perimeter_dry_run.json", estate)
    found = vpcsc(report)

    assert ("unverified", "vpcsc_protection", NAME) in triples(found)
    assert "no 'spec' block" in messages(found, "unverified", "vpcsc_protection")
    assert not [v for v in found if v.status == "contradicted"]


# -- the empty-versus-absent asymmetry (both branches) ------------------------


def _old_perimeter(**status) -> dict:
    return {"name": NAME, "perimeterType": "PERIMETER_TYPE_REGULAR",
            "status": {"resources": [REMOVED_PROJECT],
                       "restrictedServices": ["storage.googleapis.com",
                                              REMOVED_SERVICE],
                       **status},
            "useExplicitDryRunSpec": False}


def test_absent_old_egress_key_abstains_naming_the_ambiguity(estate):
    old = _old_perimeter()
    assert "egressPolicies" not in old["status"]  # the exact ambiguity
    assert detect_kind(old) == "vpc_sc_perimeter"

    report = ground_policy(POLICIES / "vpcsc_perimeter_shrunk.json", estate,
                           baseline=old)
    found = vpcsc(report)

    assert ("unverified", "vpcsc_egress", NAME) in triples(found)
    ambiguous = messages(found, "unverified", "vpcsc_egress")
    assert "indistinguishable offline" in ambiguous
    assert "egress widening was not decided" in ambiguous
    # Check 1 is unaffected: set algebra needs no key-presence guess.
    assert ("contradicted", "vpcsc_protection", NAME) in triples(found)


@pytest.mark.skipif(not HAVE_Z3, reason="the widening comparison needs z3")
def test_empty_old_egress_list_makes_any_new_egress_a_widening(estate):
    old = _old_perimeter(egressPolicies=[])
    report = ground_policy(POLICIES / "vpcsc_perimeter_shrunk.json", estate,
                           baseline=old)

    assert ("contradicted", "vpcsc_egress", NAME) in triples(vpcsc(report))
    assert "newly permits" in messages(vpcsc(report), "contradicted", "vpcsc_egress")


# -- the bridge demotion ------------------------------------------------------


def test_regular_to_bridge_is_contradicted(estate):
    old = _old_perimeter(egressPolicies=[])
    new = {"name": NAME, "perimeterType": "PERIMETER_TYPE_BRIDGE",
           "status": {"resources": [REMOVED_PROJECT],
                      "restrictedServices": ["storage.googleapis.com",
                                             REMOVED_SERVICE],
                      "egressPolicies": []},
           "useExplicitDryRunSpec": False}

    report = ground_policy(new, estate, baseline=old)
    found = vpcsc(report)

    assert ("contradicted", "vpcsc_protection", NAME) in triples(found)
    demotion = messages(found, "contradicted", "vpcsc_protection")
    assert "a bridge enforces nothing" in demotion
    # Nothing was dropped from either list — the demotion alone is the finding.
    assert REMOVED_PROJECT not in demotion


# -- backend honesty ----------------------------------------------------------


def _pair_context(solver, new_name: str, baseline: dict) -> CheckContext:
    doc = load(new_name)
    return CheckContext(snapshot=GcpSnapshot.load(FIXTURES / "estate_snapshot.json"),
                        solver=solver, document=doc, document_kind="vpc_sc_perimeter",
                        source=new_name, claims=tuple(perimeter_claims(doc)),
                        baseline=baseline, baseline_kind="vpc_sc_perimeter")


def test_builtin_backend_decides_check_1_and_abstains_on_check_2():
    ctx = _pair_context(BuiltinSolver(), "vpcsc_perimeter_shrunk.json",
                        load("vpcsc_perimeter.json"))
    found = check_perimeter_pair(ctx)
    got = triples(found)

    # Check 1 is set algebra: it decides identically with or without z3.
    assert ("contradicted", "vpcsc_protection", NAME) in got
    assert REMOVED_PROJECT in messages(found, "contradicted", "vpcsc_protection")
    # Check 2 needs the solver and says exactly why it could not answer.
    assert ("unverified", "vpcsc_egress", NAME) in got
    assert "z3 is not available" in messages(found, "unverified", "vpcsc_egress")


# -- registration and scope ---------------------------------------------------


def test_registered_as_a_document_check_and_a_pair_check():
    assert DOCUMENT_CHECKS == (check_perimeter_estate,)
    assert PAIR_CHECKS == {"vpc_sc_perimeter": check_perimeter_pair}
    assert check_perimeter_estate in registry.document_checks()
    assert registry.pair_check("vpc_sc_perimeter") is check_perimeter_pair


def test_a_baseline_that_is_not_a_perimeter_abstains(estate):
    report = ground_policy(POLICIES / "vpcsc_perimeter_shrunk.json", estate,
                           baseline=POLICIES / "iam_policy_good.json")
    found = vpcsc(report)

    assert triples(found) == [("unverified", "vpcsc_protection", NAME)]
    assert "not recognized as a service perimeter" in found[0].message


def test_the_estate_check_stays_silent_on_other_documents(estate):
    for name in ("iam_policy_good.json", "org_policy_bad.json", "tf_plan_full.json"):
        report = ground_policy(POLICIES / name, estate)
        assert vpcsc(report) == [], name


def test_the_estate_check_defers_to_the_baseline(estate):
    doc = load("vpcsc_perimeter_shrunk.json")
    ctx = CheckContext(snapshot=estate, solver=get_solver(), document=doc,
                       document_kind="vpc_sc_perimeter", source="<doc>",
                       claims=tuple(perimeter_claims(doc)),
                       baseline=load("vpcsc_perimeter.json"),
                       baseline_kind="vpc_sc_perimeter")
    # Both paths would fire on this document; only the PAIR path may, or the
    # same removal would be reported twice.
    assert check_perimeter_estate(ctx) == []
    assert check_perimeter_pair(ctx)
