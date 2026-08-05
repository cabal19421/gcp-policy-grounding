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

RECORD GUARDS (the two sections below). Four defects were reproduced by
execution, each with a byte-identical well-formed control that still decides.
TEST-FAILS-FIRST, against the code as it stood (the pre-fix module was shimmed
with the three tri-state names so the failures are behavioural, not imports)::

    $ .venv/bin/python -m pytest -q tests/test_gcp_vpcsc_checks.py
    FAILED …::test_a_drifted_baseline_protection_list_abstains_naming_the_field
    FAILED …::test_a_drifted_estate_protection_list_abstains_naming_the_field
    FAILED …::test_an_old_side_that_omits_resources_abstains
      AssertionError: assert ('unverified', 'vpcsc_protection', …) in
        [('grounded', 'vpcsc_protection', …), …]
    FAILED …::test_removing_nothing_from_an_empty_kept_set_is_not_a_pass
    FAILED …::test_the_old_policy_list_is_absent_empty_or_unreadable_and_never_one_of_two
    FAILED …::test_an_unreadable_old_axis_aborts_that_direction
      AssertionError: assert ('unverified', 'vpcsc_egress', …) in
        [('grounded', 'vpcsc_egress', …), …]
    FAILED …::test_an_unreadable_old_axis_may_not_reach_the_old_predicate
      TypeError: _axis_pred() got an unexpected keyword argument 'unreadable_is_any'
    7 failed, 17 passed

In the first three the check announced, with ``report.ok`` True, that a proposal
EMPTYING the perimeter removes nothing and it "still protects 0 project(s)"; in
the sixth, that a strictly wider method permits nothing new.

``test_an_old_record_omitting_a_policy_list_never_contradicts`` is the eighth,
and is the one that does NOT fail first: it is the record-level pin the review
found entirely uncovered, so that deleting the absent-versus-empty guard stops
leaving the perimeter suite green. Measured with that guard replaced by
``return True``, it fails alongside
``test_absent_old_egress_key_abstains_naming_the_ambiguity`` and nothing else.

Environment-honest like ``test_gcp_preflight``: every expectation that needs the
solver branches on whether z3 is importable.
"""

import copy
import json
from pathlib import Path

import pytest

from gcp_grounding import registry
from gcp_grounding.core.solver import BuiltinSolver, get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import detect_kind, ground_policy
from gcp_grounding.registry import CheckContext
from gcp_grounding.vpcsc_checks import (
    DOCUMENT_CHECKS, LITERALS, PAIR_CHECKS, UNREADABLE, WILDCARD, _Axis,
    _axis_pred, _check_widening, _literals, check_perimeter_estate,
    check_perimeter_pair,
)
from gcp_grounding.vpcsc_claims import perimeter_claims
from tests.lineno_invariant import assert_no_line_numbers

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


# -- the record guards: absent versus empty -----------------------------------
#
# The list coercion returned [] for anything that was not a list — including the
# None of an absent key, which is what the real API sends for an empty list — so
# the removal difference came out empty and the check announced that a proposal
# EMPTYING the perimeter removes nothing and "still protects 0 project(s)".


#: A proposal that clears the perimeter completely and proposes no policy at all,
#: so the only thing under test is CHECK 1's differencing.
EMPTIED = {"name": NAME, "perimeterType": "PERIMETER_TYPE_REGULAR",
           "status": {"resources": [], "restrictedServices": [],
                      "accessLevels": [], "ingressPolicies": [],
                      "egressPolicies": []},
           "useExplicitDryRunSpec": False}


def _old_lists(resources, services) -> dict:
    """A previous perimeter that differs from the well-formed control ONLY in
    the shape of the two set-valued protection fields."""
    return {"name": NAME, "perimeterType": "PERIMETER_TYPE_REGULAR",
            "status": {"resources": resources, "restrictedServices": services,
                       "ingressPolicies": [], "egressPolicies": []},
            "useExplicitDryRunSpec": False}


def test_a_drifted_baseline_protection_list_abstains_naming_the_field(estate):
    # MEASURED: `resources` a string and `restrictedServices` an object. Both
    # coerced to [], so the removal set was empty and the perimeter that keeps
    # nothing was reported as removing nothing.
    drifted = _old_lists("projects/123456", {"0": "storage.googleapis.com"})
    report = ground_policy(EMPTIED, estate, baseline=drifted)
    found = vpcsc(report)

    assert ("unverified", "vpcsc_protection", NAME) in triples(found)
    said = messages(found, "unverified", "vpcsc_protection")
    assert "'status.resources' is str, not a list" in said
    assert "'status.restricted_services' is dict, not a list" in said
    assert not [v for v in found if v.status == "grounded"
                and v.kind == "vpcsc_protection"]

    # The byte-identical well-formed control still decides, and contradicts.
    control = _old_lists(["projects/123456"], ["storage.googleapis.com"])
    controlled = vpcsc(ground_policy(EMPTIED, estate, baseline=control))
    assert ("contradicted", "vpcsc_protection", NAME) in triples(controlled)
    removal = messages(controlled, "contradicted", "vpcsc_protection")
    assert REMOVED_PROJECT in removal and "storage.googleapis.com" in removal


def _drifted_estate(**status) -> GcpSnapshot:
    """The committed estate snapshot with the named ``status`` fields replaced.

    ``estate_snapshot.json`` is byte-pinned by ``test_gcp_estate_fixture``, so
    the drift is applied to a round-tripped copy — and the loader ACCEPTS it,
    which is the point: only ``status``/``spec`` themselves are shape-checked.
    """
    data = copy.deepcopy(GcpSnapshot.load(FIXTURES / "estate_snapshot.json").to_dict())
    data["vpc_sc_perimeters"][NAME]["status"].update(status)
    return GcpSnapshot.from_dict(data)


def test_a_drifted_estate_protection_list_abstains_naming_the_field(estate):
    # The same drift needs no malformed *document*: it can sit in the captured
    # record, which the snapshot loader accepts.
    drifted = _drifted_estate(resources="projects/123456",
                              restricted_services={"0": "storage.googleapis.com"})
    found = vpcsc(ground_policy(EMPTIED, drifted))

    assert ("unverified", "vpcsc_protection", NAME) in triples(found)
    said = messages(found, "unverified", "vpcsc_protection")
    assert "'status.resources' is str, not a list" in said
    assert "'status.restricted_services' is dict, not a list" in said
    assert not [v for v in found if v.status == "grounded"
                and v.kind == "vpcsc_protection"]

    # The control is the committed record itself, unmodified — and it decides.
    controlled = vpcsc(ground_policy(EMPTIED, estate))
    assert ("contradicted", "vpcsc_protection", NAME) in triples(controlled)
    assert REMOVED_PROJECT in messages(controlled, "contradicted", "vpcsc_protection")


def test_an_old_side_that_omits_resources_abstains(estate):
    # No malformed input at all: the real API OMITS `resources` for an empty
    # list, so absent and captured-empty are indistinguishable offline — exactly
    # the ambiguity the policy lists were already guarded for.
    absent = _old_lists([], ["storage.googleapis.com"])
    del absent["status"]["resources"]
    new = copy.deepcopy(EMPTIED)
    new["status"]["restrictedServices"] = ["storage.googleapis.com"]

    found = vpcsc(ground_policy(new, estate, baseline=absent))
    assert ("unverified", "vpcsc_protection", NAME) in triples(found)
    said = messages(found, "unverified", "vpcsc_protection")
    assert "'status.resources' is absent" in said
    assert "indistinguishable offline" in said
    assert not [v for v in found if v.status == "grounded"
                and v.kind == "vpcsc_protection"]

    # Byte-identical apart from the key being present and empty: a captured
    # empty list is decidable, and this proposal removes nothing from it.
    control = _old_lists([], ["storage.googleapis.com"])
    controlled = vpcsc(ground_policy(new, estate, baseline=control))
    assert ("unverified", "vpcsc_protection", NAME) in triples(controlled)
    assert "empty kept-set" in messages(controlled, "unverified", "vpcsc_protection")


def test_an_unreadable_protection_field_abstains_while_a_readable_one_differences(estate):
    # MK-V02, both polarities in one record: `resources` is PRESENT with a shape
    # nobody can read, so it is reported unreadable and differenced against
    # nothing, while `restrictedServices` is a well-formed list and IS
    # differenced — and really does lose an entry.
    old = _old_lists("projects/123456", ["storage.googleapis.com", REMOVED_SERVICE])
    new = copy.deepcopy(EMPTIED)
    new["status"]["restrictedServices"] = ["storage.googleapis.com"]
    found = [v for v in vpcsc(ground_policy(new, estate, baseline=old))
             if v.kind == "vpcsc_protection"]

    unread = messages(found, "unverified", "vpcsc_protection")
    assert "'status.resources' is str, not a list" in unread
    assert "was not differenced against the proposal's" in unread
    assert "restricted_services" not in unread

    removal = messages(found, "contradicted", "vpcsc_protection")
    assert REMOVED_SERVICE in removal and "lose VPC-SC protection" in removal
    assert REMOVED_PROJECT not in removal  # the unreadable field found nothing
    assert not [v for v in found if v.status == "grounded"]


def test_removing_nothing_from_an_empty_kept_set_is_not_a_pass(estate):
    # Both sides readable, both empty: nothing is removed, and there is also
    # nothing left behind the perimeter. "Still protects 0 project(s)" is not a
    # statement about protection.
    old = _old_lists([], [])
    found = vpcsc(ground_policy(EMPTIED, estate, baseline=old))

    assert ("unverified", "vpcsc_protection", NAME) in triples(found)
    said = messages(found, "unverified", "vpcsc_protection")
    assert "no project and no restricted service" in said
    assert "protects nothing" in said
    assert not [v for v in found if v.status == "grounded"
                and v.kind == "vpcsc_protection"]

    # The control keeps something, so the same "removes nothing" grounds.
    kept = copy.deepcopy(EMPTIED)
    kept["status"]["resources"] = [REMOVED_PROJECT]
    kept["status"]["restrictedServices"] = ["storage.googleapis.com"]
    controlled = vpcsc(ground_policy(kept, estate,
                                     baseline=_old_lists([REMOVED_PROJECT],
                                                         ["storage.googleapis.com"])))
    assert ("grounded", "vpcsc_protection", NAME) in triples(controlled)
    assert "still protects 1 project(s)" in messages(
        controlled, "grounded", "vpcsc_protection")


def test_a_one_sided_empty_kept_set_abstains_rather_than_grounding(estate):
    # MK-V01: the empty kept-set is an abstention field by field, not only when
    # BOTH are empty. A perimeter left with projects but no restricted service
    # restricts nothing, and one left with restricted services but no project
    # holds nothing behind them — either way "still protects" is not a statement
    # about protection.
    def proposal(resources, services) -> dict:
        new = copy.deepcopy(EMPTIED)
        new["status"]["resources"] = resources
        new["status"]["restrictedServices"] = services
        return new

    def protection(resources, services):
        # The old side is byte-identical to the new one, so nothing is removed
        # and the kept-set is the only thing under test.
        report = ground_policy(proposal(resources, services), estate,
                               baseline=_old_lists(resources, services))
        [verdict] = [v for v in vpcsc(report) if v.kind == "vpcsc_protection"]
        return verdict

    no_service = protection([REMOVED_PROJECT], [])
    assert no_service.status == "unverified"
    assert "keeps no restricted service" in no_service.message
    assert "protects nothing" in no_service.message

    no_project = protection([], ["storage.googleapis.com"])
    assert no_project.status == "unverified"
    assert "keeps no project" in no_project.message
    assert "protects nothing" in no_project.message

    # The control keeps both, so the same "removes nothing" grounds.
    both = protection([REMOVED_PROJECT], ["storage.googleapis.com"])
    assert both.status == "grounded"
    assert "still protects 1 project(s)" in both.message
    assert "1 restricted service(s)" in both.message


def test_an_old_record_omitting_a_policy_list_never_contradicts(estate):
    # The RECORD-level pin the review found entirely uncovered: deleting the
    # absent-versus-empty guard leaves every end-to-end perimeter test green,
    # because none of them puts a policy-proposing document against a record
    # that OMITS the list. An absent old list must abstain, and must never be
    # read as "none permitted" — which would make this a false widening.
    data = copy.deepcopy(GcpSnapshot.load(FIXTURES / "estate_snapshot.json").to_dict())
    del data["vpc_sc_perimeters"][NAME]["status"]["egress_policies"]
    record = GcpSnapshot.from_dict(data)

    doc = load("vpcsc_perimeter_shrunk.json")
    ctx = CheckContext(snapshot=record, solver=get_solver(), document=doc,
                       document_kind="vpc_sc_perimeter", source="<doc>",
                       claims=tuple(perimeter_claims(doc)))
    found = [v for v in check_perimeter_estate(ctx) if v.kind == "vpcsc_egress"]

    assert [(v.status, v.kind, v.target) for v in found] == [
        ("unverified", "vpcsc_egress", NAME)]
    assert "'status.egress_policies' key" in found[0].message
    assert "indistinguishable offline" in found[0].message

    # The captured record itself carries the key, so the same proposal decides.
    kept = CheckContext(snapshot=estate, solver=get_solver(), document=doc,
                        document_kind="vpc_sc_perimeter", source="<doc>",
                        claims=tuple(perimeter_claims(doc)))
    decided = [v for v in check_perimeter_estate(kept) if v.kind == "vpcsc_egress"]
    assert [v.status for v in decided] == ["contradicted" if HAVE_Z3 else "unverified"]


def test_the_old_policy_list_is_absent_empty_or_unreadable_and_never_one_of_two(estate):
    # Three outcomes, not two. The middle one is the only decidable reading, and
    # the third did not exist before: an old list that is PRESENT with a shape
    # nobody can read normalized to [], which `_allowed` reads as "none
    # permitted" — a false widening manufactured out of an unreadable old side.
    absent = _old_perimeter()
    empty = _old_perimeter(egressPolicies=[])
    unreadable = _old_perimeter(egressPolicies="see the other perimeter")

    def egress(old):
        report = ground_policy(POLICIES / "vpcsc_perimeter_shrunk.json", estate,
                               baseline=old)
        return [v for v in vpcsc(report) if v.kind == "vpcsc_egress"]

    [gap] = egress(absent)
    assert gap.status == "unverified"
    assert "indistinguishable offline" in gap.message

    [observed] = egress(empty)
    assert observed.status == ("contradicted" if HAVE_Z3 else "unverified")

    [bad] = egress(unreadable)
    assert bad.status == "unverified"
    assert "'status.egress_policies' is str, not a list" in bad.message
    assert "can only HIDE a widening" in bad.message


# -- the record guards: directional readability -------------------------------


PRINCIPAL = "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com"
WIDER_METHOD = "google.storage.objects.create"


def _egress(selectors) -> dict:
    """A perimeter whose single egress policy differs only in *selectors*."""
    return {"name": NAME, "perimeterType": "PERIMETER_TYPE_REGULAR",
            "status": {"resources": [REMOVED_PROJECT],
                       "restrictedServices": ["storage.googleapis.com"],
                       "ingressPolicies": [],
                       "egressPolicies": [{
                           "egressFrom": {"identities": [PRINCIPAL]},
                           "egressTo": {
                               "resources": [REMOVED_PROJECT],
                               "operations": [{
                                   "serviceName": "storage.googleapis.com",
                                   "methodSelectors": selectors}]}}]},
            "useExplicitDryRunSpec": False}


@pytest.mark.skipif(not HAVE_Z3, reason="the widening comparison needs z3")
def test_an_unreadable_old_axis_aborts_that_direction(estate):
    # MEASURED: an old policy identical to the new one except that one selector
    # list is a bare string. The axis predicate mapped it to "all methods" —
    # over-approximating the OLD side, which can only HIDE a widening — and the
    # strictly wider new method was reported as permitting nothing new.
    new = _egress([{"method": "google.storage.objects.get"},
                   {"method": WIDER_METHOD}])
    drifted = _egress("google.storage.objects.get")
    found = vpcsc(ground_policy(new, estate, baseline=drifted))

    assert ("unverified", "vpcsc_egress", NAME) in triples(found)
    said = messages(found, "unverified", "vpcsc_egress")
    assert NAME in said and "'status'" in said and "egress" in said
    assert "method axis could not be read" in said
    assert "operations[0].method_selectors is str, not a list" in said
    assert "can only HIDE a widening" in said

    # The byte-identical well-formed control contradicts, and names both the
    # principal it lets out and the method that is new.
    control = _egress([{"method": "google.storage.objects.get"}])
    controlled = vpcsc(ground_policy(new, estate, baseline=control))
    assert ("contradicted", "vpcsc_egress", NAME) in triples(controlled)
    widening = messages(controlled, "contradicted", "vpcsc_egress")
    assert PRINCIPAL in widening and WIDER_METHOD in widening


def test_an_unreadable_old_axis_may_not_reach_the_old_predicate():
    # The asymmetry, at the predicate itself: UNREADABLE is "every value" only
    # where the caller says over-approximating is safe, which is the NEW side.
    z3 = pytest.importorskip("z3")
    var = z3.String("axis")
    unreadable = _Axis(UNREADABLE, detail="'identities' is str, not a list")

    assert z3.is_true(_axis_pred(z3, var, unreadable, unreadable_is_any=True))
    with pytest.raises(ValueError, match="must abstain"):
        _axis_pred(z3, var, unreadable, unreadable_is_any=False)

    # The other two states are symmetric and never depend on the flag.
    for flag in (True, False):
        assert z3.is_true(_axis_pred(z3, var, _Axis(WILDCARD), unreadable_is_any=flag))
        assert z3.is_true(_axis_pred(z3, var, _Axis(LITERALS, ("*",)),
                                     unreadable_is_any=flag))
        assert not z3.is_true(_axis_pred(z3, var, _Axis(LITERALS, ("a",)),
                                         unreadable_is_any=flag))


class _StubZ3:
    """Just enough of z3 for :func:`_axis_pred`'s two constant branches, so the
    asymmetry is pinned in every environment and not only where z3 imports."""

    def BoolVal(self, value):
        return ("BoolVal", value)


def test_an_unreadable_old_axis_abstains_while_an_unreadable_new_axis_still_contradicts(
        estate):
    # MK-V03, the asymmetry the tri-state exists for. UNREADABLE is "every
    # value" on the NEW side only: over-approximating what a proposal permits
    # can only over-report a widening, while over-approximating the PREVIOUS
    # permission set can only hide one.
    unreadable = _Axis(UNREADABLE, detail="'identities' is str, not a list")
    assert _axis_pred(_StubZ3(), None, unreadable,
                      unreadable_is_any=True) == ("BoolVal", True)
    with pytest.raises(ValueError, match="must abstain"):
        _axis_pred(_StubZ3(), None, unreadable, unreadable_is_any=False)

    # The measured masked widening: the OLD side's selector list is a bare
    # string against a new policy granting a strictly wider method. That
    # direction aborts, naming the perimeter, the side, the direction and the
    # axis, instead of reporting that nothing new is permitted.
    new = _egress([{"method": "google.storage.objects.get"},
                   {"method": WIDER_METHOD}])
    report = ground_policy(new, estate, baseline=_egress("google.storage.objects.get"))
    [aborted] = [v for v in vpcsc(report) if v.kind == "vpcsc_egress"]
    assert aborted.status == "unverified"
    assert NAME in aborted.message and "'status'" in aborted.message
    assert "egress method axis could not be read" in aborted.message
    assert "can only HIDE a widening" in aborted.message

    if HAVE_Z3:
        # The mirror image on the NEW side stays a DECISION: the unreadable
        # axis is read as every method, which can only over-report.
        ctx = CheckContext(snapshot=estate, solver=get_solver(), document={},
                           document_kind="vpc_sc_perimeter", source="<doc>",
                           claims=())
        [decided] = _check_widening(
            "egress", _egress("google.storage.objects.get")["status"],
            _egress([{"method": "google.storage.objects.get"}]),
            NAME, "<doc>", "status", "", ctx)
        assert decided.status == "contradicted"
        assert PRINCIPAL in decided.message


def test_a_non_string_axis_entry_is_unreadable_and_a_clean_list_is_literals():
    # MK-V04, the tri-state at its input. A malformed entry used to be dropped
    # silently, which reads downstream as an axis that never declared it.
    junk = _literals({"identities": [PRINCIPAL, 7]}, "identities")
    assert junk.state == UNREADABLE
    assert junk.detail == "identities[1] is int, not a string"
    assert junk.literals == ()

    clean = _literals({"identities": [PRINCIPAL, "user:ada@example.com"]},
                      "identities")
    assert clean.state == LITERALS
    assert clean.literals == (PRINCIPAL, "user:ada@example.com")
    assert clean.detail == ""


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


# -- the shared lineno invariant ----------------------------------------------


def _variants(perimeter: dict) -> list[dict]:
    """The committed perimeter with one field changed per copy — the shapes
    ``_compare`` and ``_widening`` branch on that no committed document has:
    a missing side block, a REGULAR→BRIDGE demotion, a different name, an
    emptied policy list and an absent policy key."""
    status = perimeter["status"]
    return [
        {k: v for k, v in perimeter.items() if k != "status"},
        {k: v for k, v in perimeter.items() if k != "spec"},
        dict(perimeter, perimeterType="PERIMETER_TYPE_BRIDGE"),
        dict(perimeter, name=NAME.replace("/prod", "/other")),
        dict(perimeter, status=dict(status, egressPolicies=[])),
        dict(perimeter,
             status={k: v for k, v in status.items() if k != "egressPolicies"}),
    ]


def _unreadable_priors(perimeter: dict) -> list[tuple[dict, str, str]]:
    """``(prior, kind, the reason it must name)`` per OLD-side abstention — the
    committed perimeter with one field changed per copy into a shape nothing
    can READ. Every ``_variants`` entry above is well-formed, so none of them
    reaches an unreadable protection field (``vpcsc_checks.py:253``), a policy
    list that is not a list (:575), or a readable policy whose axis cannot be
    read (:587)."""
    status = perimeter["status"]
    return [
        (dict(perimeter, status=dict(status, resources=REMOVED_PROJECT)),
         "vpcsc_protection",
         "'resources' could not be read ('status.resources' is str, not a list)"),
        (dict(perimeter, status=dict(status, egressPolicies="nope")),
         "vpcsc_egress", "'status.egress_policies' is str, not a list"),
        (dict(perimeter, status=dict(status, egressPolicies=[
            {"egressFrom": {"identities": "not-a-list"},
             "egressTo": {"operations": []}}])),
         "vpcsc_egress",
         "egress identity axis could not be read ('identities' is str, not a list)"),
    ]


def test_no_vpcsc_verdict_carries_a_line_number(estate, partial, monkeypatch):
    """Every arm of this module reports ``lineno`` 0 — see lineno_invariant.

    Drives the three committed perimeters and the variants above over both
    estate snapshots, each as every other's ``--baseline`` (plus a
    non-perimeter one), the unreadable priors below, and the whole matrix again
    with the builtin backend forced — the only way to reach the z3-absent
    widening abstention here.
    """
    docs = [load(n) for n in ("vpcsc_perimeter.json",
                              "vpcsc_perimeter_shrunk.json",
                              "vpcsc_perimeter_dry_run.json")]
    docs += _variants(docs[0])
    reports = []
    for builtin in (False, True):
        if builtin:
            monkeypatch.setattr("gcp_grounding.preflight.get_solver",
                                lambda *a, **k: get_solver(prefer="builtin"))
        for doc in docs:
            for snapshot in (estate, partial):
                reports.append(ground_policy(doc, snapshot))
                for other in docs + [load("iam_policy_good.json")]:
                    reports.append(ground_policy(doc, snapshot, baseline=other))
    for prior, kind, reason in _unreadable_priors(docs[0]):
        report = ground_policy(docs[0], estate, baseline=prior)
        reports.append(report)
        # Identity, not shape: each path is pinned to have DECIDED — status,
        # kind, target and the reason it names — so the lineno 0 beside it is
        # a decision's, not some fail-open branch's.
        assert any(v.status == "unverified" and v.kind == kind
                   and v.target == NAME and reason in v.message
                   for v in vpcsc(report)), [(v.kind, v.message) for v in
                                             vpcsc(report)]

    # Non-vacuity: the drive really decides, in all three directions.
    assert {v.status for r in reports for v in vpcsc(r)} == {
        "unverified", "grounded", "contradicted"}
    for report in reports:
        assert_no_line_numbers(report)
