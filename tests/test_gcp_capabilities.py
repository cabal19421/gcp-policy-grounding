"""The capability probes themselves, under mutation.

A probe exists to answer one question — CAN THE REAL CODE DECIDE THIS FAMILY —
so the only way to test it is to break the code in the ways a presence check
misses and require the probe to notice:

* GUTTED DISPATCH. Empty the tuple/map the family's checks are dispatched
  through. The module is still importable and every kind is still in the
  vocabulary, so ``find_spec`` and ``have_claim_kinds`` both keep answering
  True. The probe must go dead, because nothing can block any more.
* A RUBBER STAMP. Rewrite the owning check to answer with the family's
  ``decided`` status whatever it is handed. A one-sided probe — one that only
  asks "did the bad input get blocked?" — calls this LIVE, and the family then
  collects greens from a stamp. The GOOD near-twin is what kills it:
  ``test_the_rubber_stamp_passes_the_old_probes_and_fails_the_new_one`` runs
  exactly that comparison and records the result.
* A NEUTERED CHECK. The opposite polarity: the arm that decides is rewritten
  to ``grounded``, so nothing is ever blocked. The BAD half kills that one.

Three capabilities are decided by checks THIS checkout ships — ``iam_existence``
(the Datalog existence pass), ``tf_claims`` (the terraform extractor) and
``org_constraint_value`` (the value-type check) — and every mutation above is
executed against them for real. The six domain capabilities have no checker
here yet, so for those the assertion is the other half of the contract: the
probe measures dead, never raises, and says in its reason what it saw.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import socket
import subprocess
from pathlib import Path

import pytest

from gcp_grounding.claims import Claim
from gcp_grounding.core.report import STATUSES, GroundingReport, Verdict
from tests.agentic import capabilities, env
from tests.agentic.asserts import FAMILY_KINDS, INCIDENTAL_KINDS

ALL_CAPABILITIES = list(capabilities.CAPABILITIES.values())
CAPABILITY_IDS = [cap.name for cap in ALL_CAPABILITIES]

#: The capabilities this checkout really decides — the ones whose mutants can be
#: EXECUTED rather than merely described.
LIVE_NAMES = ("iam_existence", "tf_claims", "org_constraint_value")

#: ``env._module_available`` may name only components with no
#: ``ground_policy`` channel to measure. Everything a check decides is probed
#: behaviourally; see ``test_module_presence_checks_stay_pinned``.
ALLOWED_PRESENCE_CHECKS = frozenset({
    "gcp_grounding.sec_rules",
    "gcp_grounding.sec_compile",
    "gcp_grounding.bash_mutation",
})

#: env probe name → the capability it must delegate to.
DELEGATES = {
    "HAVE_TF_CLAIMS": capabilities.TF_CLAIMS,
    "HAVE_FIREWALL_DOMAIN": capabilities.FIREWALL,
    "HAVE_HIER_FIREWALL_DOMAIN": capabilities.HIER_FIREWALL,
    "HAVE_ARMOR_DOMAIN": capabilities.ARMOR,
    "HAVE_VPCSC_DOMAIN": capabilities.VPCSC,
    "HAVE_PUBLIC_PRINCIPAL": capabilities.PUBLIC_PRINCIPAL,
    "HAVE_ORG_ENFORCEMENT": capabilities.ORG_ENFORCEMENT,
}


@pytest.fixture(autouse=True)
def _fresh_probes():
    """The probe cache is session-memoized on purpose; a mutation test must not
    read a value measured before its monkeypatch, nor leave one behind."""
    capabilities.probe.cache_clear()
    yield
    capabilities.probe.cache_clear()


def measure(cap):
    """Probe *cap* against the code as it stands right now."""
    capabilities.probe.cache_clear()
    return capabilities.probe(cap)


# -- mutations ----------------------------------------------------------------


def gut(monkeypatch, cap) -> int:
    """Empty every dispatch table *cap* declares; → how many were emptied.

    ``type(current)()`` is an empty container of the same type, which is the
    emptied ``DOCUMENT_CHECKS`` tuple / ``PAIR_CHECKS`` map in this checkout's
    vocabulary: the existence-kind tuple ``preflight`` dispatches on and the
    terraform extractor map.
    """
    for module_name, attribute in cap.guts:
        module = importlib.import_module(module_name)
        current = getattr(module, attribute)
        monkeypatch.setattr(module, attribute, type(current)())
    return len(cap.guts)


def _stamped_existence(status):
    def ground_existence(claims, snapshot, report=None):
        report = GroundingReport() if report is None else report
        for claim in claims:
            report.add(Verdict(status, claim.kind, claim.value, 0,
                               f"{claim.location}: stamped {status}"))
        return report

    return ground_existence


def stamp(monkeypatch, cap, status) -> None:
    """Rewrite *cap*'s owning check to answer *status* whatever it is handed."""
    if cap.name == "iam_existence":
        preflight = importlib.import_module("gcp_grounding.preflight")
        monkeypatch.setattr(preflight, "ground_existence",
                            _stamped_existence(status))
    elif cap.name == "org_constraint_value":
        preflight = importlib.import_module("gcp_grounding.preflight")
        monkeypatch.setattr(
            preflight, "check_constraint_value",
            lambda claim, snapshot: Verdict(status, "constraint", claim.value,
                                            0, f"stamped {status}"))
    elif cap.name == "tf_claims":
        # A hardcoded result, the shape the review's subset-check mutant had:
        # every resource claims the same role, so the answer no longer depends
        # on the input at all.
        tf_claims = importlib.import_module("gcp_grounding.tf_claims")
        role = ("roles/bigquery.reader" if status == "ungrounded"
                else "roles/bigquery.dataViewer")
        hardcoded = lambda address, values: [  # noqa: E731 — one expression
            Claim("role", role, f"{address}.role")]
        monkeypatch.setattr(tf_claims, "_EXTRACTORS",
                            dict.fromkeys(tf_claims._EXTRACTORS, hardcoded))
    else:
        raise AssertionError(f"no stamp is defined for {cap.name!r}")


# -- the declaration contract -------------------------------------------------


@pytest.mark.parametrize("cap", ALL_CAPABILITIES, ids=CAPABILITY_IDS)
def test_capability_kinds_are_its_own_family_channel(cap):
    """CHANNEL DISCIPLINE at the probe: a capability may only be satisfied by
    kinds its family OWNS, and never by the incidental vocabulary every
    terraform document hits for free."""
    assert cap.family in FAMILY_KINDS, cap.name
    assert cap.kinds, cap.name
    assert cap.kinds <= FAMILY_KINDS[cap.family], (
        f"{cap.name} claims kinds outside its family's channel: "
        f"{sorted(cap.kinds - FAMILY_KINDS[cap.family])}")
    assert cap.kinds.isdisjoint(INCIDENTAL_KINDS), (
        f"{cap.name} would be satisfied by incidental vocabulary: "
        f"{sorted(cap.kinds & INCIDENTAL_KINDS)}")


@pytest.mark.parametrize("cap", ALL_CAPABILITIES, ids=CAPABILITY_IDS)
def test_capability_decides_with_a_finding_status(cap):
    assert cap.decided in STATUSES, cap.name
    # `grounded` and `unverified` are not decisions a bad input may satisfy: a
    # probe keyed off either would call an abstaining gate live.
    assert cap.decided in ("ungrounded", "contradicted"), cap.name


def test_probe_is_memoized_per_session():
    first = capabilities.probe(capabilities.IAM_EXISTENCE)
    assert capabilities.probe(capabilities.IAM_EXISTENCE) is first


def test_the_live_capabilities_are_live():
    """The anchor every mutation assertion below is measured against: without
    it, "the probe went dead" is satisfied by a probe that was never alive."""
    for name in LIVE_NAMES:
        cap = capabilities.CAPABILITIES[name]
        result = measure(cap)
        assert result.live is True, f"{name}: {result.reason}"
        assert result.reason == ""


# -- mutation 1: the dispatch is gutted ---------------------------------------


@pytest.mark.parametrize("cap", ALL_CAPABILITIES, ids=CAPABILITY_IDS)
def test_a_gutted_dispatch_kills_the_probe(cap, monkeypatch):
    """Empty this capability's dispatch tables and the probe must measure dead,
    naming the family — the module is still on disk and the vocabulary is
    untouched, so a presence check sees nothing wrong.

    A capability with no dispatch table in this checkout has no checker either;
    it is already dead, and the same two assertions hold for the same reason.
    """
    gut(monkeypatch, cap)
    result = measure(cap)
    assert result.live is False, cap.name
    assert cap.family in result.reason, result.reason
    assert cap.name in result.reason, result.reason


@pytest.mark.parametrize("name", LIVE_NAMES)
def test_gutting_flips_a_live_capability_dead(name, monkeypatch):
    """The executed form of the test above: live BEFORE the mutation, dead
    after, with the dispatch table emptied and nothing else touched."""
    cap = capabilities.CAPABILITIES[name]
    assert measure(cap).live is True
    assert gut(monkeypatch, cap) >= 1, f"{name} declares no dispatch table"
    result = measure(cap)
    assert result.live is False
    assert cap.family in result.reason


# -- mutation 2: the check is a rubber stamp ----------------------------------


@pytest.mark.parametrize("name", LIVE_NAMES)
def test_a_rubber_stamp_kills_the_probe(name, monkeypatch):
    """The check now answers ``decided`` whatever it is handed. The BAD half of
    the probe is satisfied — that is exactly why a one-sided probe calls this
    live — and the GOOD near-twin fires too, which is what makes it dead."""
    cap = capabilities.CAPABILITIES[name]
    assert measure(cap).live is True
    stamp(monkeypatch, cap, cap.decided)
    result = measure(cap)
    assert result.live is False, f"{name} accepted a rubber stamp as a capability"
    assert "rubber stamp" in result.reason, result.reason
    assert cap.family in result.reason, result.reason


def test_the_rubber_stamp_passes_the_old_probes_and_fails_the_new_one(monkeypatch):
    """RECORDED: the mutant the old probes could not see.

    Under a hardcoded extractor every input claims the same role, so the gate
    blocks the good edit as readily as the bad one. ``find_spec`` still finds
    the module and ``"role"`` is still in ``claims.KINDS`` — both old probe
    shapes answer True, verbatim, below. The behavioural probe measures it dead.
    """
    cap = capabilities.TF_CLAIMS
    stamp(monkeypatch, cap, cap.decided)

    # The two shapes the domain gates used to be, run against the mutant:
    assert env._module_available("gcp_grounding.tf_claims") is True
    assert env.have_claim_kinds("role") is True

    # The shape they are now:
    result = measure(cap)
    assert result.live is False
    assert "rubber stamp" in result.reason


# -- mutation 3: the deciding arm is neutered ---------------------------------


@pytest.mark.parametrize("name", LIVE_NAMES)
def test_a_neutered_check_kills_the_probe(name, monkeypatch):
    """The other polarity: the arm that decides now answers ``grounded``, so
    nothing is ever blocked. The BAD half catches it — and the reason names
    what the bad input actually produced instead."""
    cap = capabilities.CAPABILITIES[name]
    assert measure(cap).live is True
    stamp(monkeypatch, cap, "grounded")
    result = measure(cap)
    assert result.live is False, f"{name} accepted a neutered check as a capability"
    assert cap.decided in result.reason, result.reason
    assert cap.family in result.reason, result.reason


# -- absent modules never raise -----------------------------------------------


def _fixture_needing_an_absent_module():
    """A bad-input fixture that cannot be built, because the checker module it
    needs is not part of this checkout — the shape every domain capability has
    before its own task lands."""
    name = "gcp_grounding.perimeter_checks"
    if importlib.util.find_spec(name) is None:
        raise ModuleNotFoundError(f"No module named {name!r}")
    return {}, capabilities.estate_snapshot()


def test_probe_never_raises_when_the_module_is_absent():
    absent = capabilities.Capability(
        name="absent_domain", family="vpcsc",
        kinds=frozenset({"vpcsc_protection"}),
        bad=_fixture_needing_an_absent_module,
        good=_fixture_needing_an_absent_module)
    result = capabilities.probe(absent)
    assert result.live is False
    assert "absent_domain" in result.reason
    assert "vpcsc" in result.reason
    assert "ModuleNotFoundError" in result.reason


@pytest.mark.parametrize("cap", ALL_CAPABILITIES, ids=CAPABILITY_IDS)
def test_every_probe_is_a_plain_bool_and_a_reason(cap):
    result = capabilities.probe(cap)
    assert isinstance(result.live, bool), cap.name
    assert isinstance(result.reason, str), cap.name
    if not result.live:
        # A skip that does not say what was measured is a silent skip.
        assert cap.name in result.reason
        assert cap.family in result.reason
        assert "held" in result.reason or "could not be grounded" in result.reason


def test_a_dead_domain_probe_reports_what_it_measured():
    """The design's worked example: the perimeter fixture produced no vpcsc
    verdict, and the firewall plan's report held only a grounded
    ``resource_type`` — an incidental vocabulary hit, which is precisely what
    must not read as a live domain."""
    firewall = capabilities.probe(capabilities.FIREWALL)
    assert firewall.live is False
    assert "resource_type" in firewall.reason
    assert "firewall_rule" in firewall.reason

    perimeter = capabilities.probe(capabilities.VPCSC)
    assert perimeter.live is False
    assert "perimeter_config" in perimeter.reason


# -- probing is in-process, offline and free ----------------------------------


def test_probing_spawns_nothing_and_opens_no_socket(monkeypatch):
    """No subprocess and no network: a probe runs at decorator time, in every
    child the suite spawns, and must cost nothing against the subprocess
    budget. A probe that spawned would be caught and degrade to dead, so the
    live anchor is the assertion that catches it."""

    def forbidden(*args, **kwargs):
        raise AssertionError("a probe must be in-process and fully offline")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    for name in LIVE_NAMES:
        assert measure(capabilities.CAPABILITIES[name]).live is True, name


# -- env delegates, structurally ----------------------------------------------


def _module_level_have_assignments():
    tree = ast.parse(Path(env.__file__).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id.startswith("HAVE_"):
                yield target.id, node.value


def _called_names(expression) -> set[str]:
    return {node.func.id for node in ast.walk(expression)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}


def test_no_domain_gate_is_a_vocabulary_lookup():
    """The DELETION, enforced structurally rather than by memory: no ``HAVE_*``
    may be computed from ``have_claim_kinds`` any more, and ``_module_available``
    may appear only for the components pinned above."""
    for name, expression in _module_level_have_assignments():
        called = _called_names(expression)
        assert "have_claim_kinds" not in called, (
            f"{name} is a vocabulary lookup again — the kind is in KINDS long "
            f"before and long after anything can decide it")
        if "_module_available" in called:
            assert name in ("HAVE_SEC_RULES", "HAVE_SEC_COMPILE",
                            "HAVE_BASH_MUTATION"), (
                f"{name} is a presence check for a module under test; probe it "
                f"behaviourally instead")


def test_module_presence_checks_stay_pinned():
    tree = ast.parse(Path(env.__file__).read_text(encoding="utf-8"))
    named = {node.args[0].value for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
             and node.func.id == "_module_available" and node.args
             and isinstance(node.args[0], ast.Constant)}
    assert named == ALLOWED_PRESENCE_CHECKS


def test_env_domain_probes_delegate_to_their_capability():
    for name, cap in DELEGATES.items():
        assert getattr(env, name) is capabilities.probe(cap).live, name
