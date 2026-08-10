"""VPC firewall check tests: PROPOSAL exposure and PAIR non-enlargement.

Split on the same ``HAVE_Z3`` idiom the constraint / packet / preflight suites
use, because the module is honest about its own dependency:

* The **builtin** branch (always runs) pins the degraded path — with
  ``get_solver(prefer="builtin")`` every check returns exactly one
  ``unverified`` naming the backend, and a report made of those still has
  ``ok`` True, so a missing z3 abstains rather than blocking or half-passing.
  It also pins the registry wiring and the applicability skips, which need no
  solver at all.
* The **z3** branch (skipped without the z3 backend) proves the two polarities:
  the exposure check asserts the bad property (sat → ``contradicted``), the pair
  check asserts the negation of non-enlargement (unsat → ``grounded``) — and the
  two abstention disciplines that carry its value, never-drop-a-rule and
  never-compare-unrelated-networks.

The checks are driven directly through a hand-built
:class:`~gcp_grounding.registry.CheckContext` rather than through
``ground_policy``: routing a ``compute#firewall`` document to the
``firewall_rule`` kind is :func:`gcp_grounding.preflight.detect_kind`'s job and
lands separately, so the branch that exercises the whole pipeline is guarded on
that kind actually being recognized here.
"""

import ipaddress
import json
import re
from pathlib import Path

import pytest

from gcp_grounding import fw_claims, preflight, registry
from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.report import GroundingReport
from gcp_grounding.core.solver import get_solver
from gcp_grounding.fw_checks import check_open_exposure, check_packet_set_pair
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.registry import CheckContext

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

HAVE_Z3 = _z3_module(get_solver()) is not None
needs_z3 = pytest.mark.skipif(not HAVE_Z3, reason="z3 solver backend is not available")

SELF_LINK = ("https://www.googleapis.com/compute/v1/"
             "projects/acme-prod/global/networks/vpc-main")
OTHER_LINK = ("https://www.googleapis.com/compute/v1/"
              "projects/acme-prod/global/networks/vpc-other")
CANONICAL = "projects/acme-prod/global/networks/vpc-main"

PRIVATE_10 = ipaddress.ip_network("10.0.0.0/8")


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def rest(**overrides) -> dict:
    """A ``compute#firewall`` document with the given fields overridden."""
    doc = {
        "kind": "compute#firewall",
        "name": "fw-rule",
        "network": SELF_LINK,
        "direction": "INGRESS",
        "priority": 1000,
        "disabled": False,
        "sourceRanges": ["10.0.0.0/8"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
    }
    doc.update(overrides)
    return doc


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


@pytest.fixture(autouse=True)
def _fresh_registry():
    """Resolve the real PROVIDER_MODULES fresh, regardless of what a prior test
    module injected into the lazy provider cache."""
    registry.reset_cache()
    yield
    registry.reset_cache()


def fw_claim(doc):
    """The one ``firewall_rule`` claim a REST firewall document makes."""
    [claim] = [c for c in fw_claims.firewall_rule_claims(doc)
               if c.kind == "firewall_rule"]
    return claim


def context(doc, snapshot, *, baseline=None, prefer=None, source="fw.json"):
    return CheckContext(
        snapshot=snapshot,
        solver=get_solver(prefer=prefer),
        document=doc,
        document_kind="firewall_rule",
        source=source,
        claims=tuple(fw_claims.firewall_rule_claims(doc)),
        baseline=baseline,
        baseline_kind="firewall_rule" if baseline is not None else None,
    )


def exposure(doc, snapshot, *, prefer=None):
    ctx = context(doc, snapshot, prefer=prefer)
    return check_open_exposure(fw_claim(doc), ctx)


def witness_src(message: str) -> ipaddress.IPv4Address:
    match = re.search(r"from (\d+\.\d+\.\d+\.\d+) to ", message)
    assert match is not None, f"no witness source in {message!r}"
    return ipaddress.ip_address(match.group(1))


# ---------------------------------------------------------------------------
# builtin branch: registration, the applicability skips, and the degraded path.
# ---------------------------------------------------------------------------


def test_the_registry_discovers_both_checks():
    # Registered by module-level table only — no edit to a shared file.
    assert check_open_exposure in registry.claim_checks("firewall_rule")
    assert registry.pair_check("firewall_rule") is check_packet_set_pair
    # And nothing else: THIS module owns no document kind and no tf resource.
    # Asserted per owning module rather than as "the registry is empty", because
    # the integrated tree has other domain modules (org_checks, hfw_checks,
    # vpcsc_checks, armor_checks, iam_checks, fw_estate) each registering their
    # own whole-document check; fw_checks contributing one would still go red.
    assert [fn for fn in registry.document_checks()
            if fn.__module__ == "gcp_grounding.fw_checks"] == []


def _egress_rule() -> dict:
    doc = rest(name="allow-https-egress", direction="EGRESS", sourceRanges=[],
               destinationRanges=["0.0.0.0/0"])
    return doc


def _deny_rule() -> dict:
    doc = rest(name="deny-ssh-world", sourceRanges=["0.0.0.0/0"],
               denied=[{"IPProtocol": "tcp", "ports": ["22"]}])
    doc.pop("allowed")
    return doc


def _disabled_rule() -> dict:
    return rest(name="allow-ssh-world-disabled", disabled=True,
                sourceRanges=["0.0.0.0/0"],
                allowed=[{"IPProtocol": "tcp", "ports": ["22"]}])


@needs_z3
@pytest.mark.parametrize("build", [_egress_rule, _deny_rule, _disabled_rule])
def test_exposure_skips_what_cannot_expose_anything(snap, build):
    # An egress rule, a deny and a disabled rule expose nothing on their own:
    # the check returns None rather than minting a verdict about them. Guarded
    # on z3 because the backend abstention is checked first and outranks the
    # skip — a missing solver is the more informative thing to report.
    assert exposure(build(), snap) is None


def test_builtin_backend_abstains_on_every_check_and_the_report_stays_ok(snap):
    # The whole point of the abstention: no z3, no verdict — but no block
    # either, and never a silent pass.
    report = GroundingReport()
    report.backend = get_solver(prefer="builtin").backend
    assert report.backend == "builtin"

    for name in ("fw_rule_open.json", "fw_rule_good.json"):
        verdict = exposure(load(name), snap, prefer="builtin")
        assert verdict is not None
        report.add(verdict)

    ctx = context(load("fw_rule_open.json"), snap,
                  baseline=load("fw_rule_baseline.json"), prefer="builtin")
    pair = check_packet_set_pair(ctx)
    assert len(pair) == 1
    for verdict in pair:
        report.add(verdict)

    assert [v.status for v in report.verdicts] == ["unverified"] * 3
    assert all("builtin" in v.message for v in report.verdicts)
    assert report.ok is True
    assert report.counts() == {"grounded": 0, "ungrounded": 0,
                               "contradicted": 0, "unverified": 3}


# ---------------------------------------------------------------------------
# z3 branch, CHECK 1: PROPOSAL exposure (assert the bad property; sat is bad).
# ---------------------------------------------------------------------------


@needs_z3
def test_open_ingress_rule_is_contradicted_naming_a_sensitive_port(snap):
    verdict = exposure(load("fw_rule_open.json"), snap)
    assert verdict.status == "contradicted"
    assert verdict.kind == "firewall_exposure"
    assert verdict.target == "fw-allow-open"
    assert "a public source" in verdict.message
    assert "tcp/22" in verdict.message or "tcp/3389" in verdict.message


@needs_z3
def test_private_sourced_rule_is_grounded(snap):
    verdict = exposure(load("fw_rule_good.json"), snap)
    assert verdict.status == "grounded"
    assert verdict.kind == "firewall_exposure"
    assert verdict.message.endswith("no public source reaches a sensitive port")


@needs_z3
def test_the_standard_iap_ssh_rule_does_not_fire(snap):
    # 35.235.240.0/20 tcp/22 is IAP TCP forwarding, not the internet: the whole
    # reason is_public carves it out.
    doc = rest(name="allow-iap-ssh", sourceRanges=["35.235.240.0/20"],
               allowed=[{"IPProtocol": "tcp", "ports": ["22"]}])
    assert exposure(doc, snap).status == "grounded"


@needs_z3
def test_the_standard_health_check_rule_does_not_fire(snap):
    doc = rest(name="allow-health-checks",
               sourceRanges=["35.191.0.0/16", "130.211.0.0/22"],
               allowed=[{"IPProtocol": "tcp", "ports": ["80", "443", "3389"]}])
    assert exposure(doc, snap).status == "grounded"


@needs_z3
def test_split_halves_are_caught_though_no_string_says_zero_zero(snap):
    # 0.0.0.0/1 + 128.0.0.0/1 is 0.0.0.0/0 by arithmetic and by nothing else:
    # a grep for "0.0.0.0/0" cannot catch this, mask equality can.
    doc = rest(name="allow-split-ssh",
               sourceRanges=["0.0.0.0/1", "128.0.0.0/1"],
               allowed=[{"IPProtocol": "tcp", "ports": ["22"]}])
    assert not any("0.0.0.0/0" in r for r in doc["sourceRanges"])
    verdict = exposure(doc, snap)
    assert verdict.status == "contradicted"
    assert "tcp/22" in verdict.message


@needs_z3
def test_an_unsupported_rule_abstains_and_never_contradicts(snap):
    doc = rest(name="allow-broken", priority="high",
               sourceRanges=["0.0.0.0/0"],
               allowed=[{"IPProtocol": "tcp", "ports": ["22"]}])
    verdict = exposure(doc, snap)
    assert verdict.status == "unverified"
    assert verdict.kind == "firewall_exposure"
    assert "priority" in verdict.message


@needs_z3
def test_an_ingress_rule_with_no_source_at_all_abstains(snap):
    # An illegal GCP shape: rule_match raises UnsupportedPacket rather than
    # treating it as match-all, and the caller turns that into an abstention.
    doc = rest(name="allow-sourceless", sourceRanges=[],
               allowed=[{"IPProtocol": "tcp", "ports": ["22"]}])
    verdict = exposure(doc, snap)
    assert verdict.status == "unverified"
    assert "source_ranges" in verdict.message


# ---------------------------------------------------------------------------
# z3 branch, CHECK 2: PAIR non-enlargement (assert the negation; unsat is good).
# ---------------------------------------------------------------------------


def pair(new_doc, baseline_doc, snapshot, *, prefer=None):
    return check_packet_set_pair(
        context(new_doc, snapshot, baseline=baseline_doc, prefer=prefer))


@needs_z3
def test_the_widening_baseline_pair_is_contradicted_with_a_public_witness(snap):
    # fw_rule_baseline.json is fw_rule_open.json narrowed to 10.0.0.0/8, so
    # opening it back up to 0.0.0.0/0 is a genuine widening.
    [verdict] = pair(load("fw_rule_open.json"), load("fw_rule_baseline.json"), snap)
    assert verdict.status == "contradicted"
    assert verdict.kind == "firewall_pair"
    assert verdict.target == f"{CANONICAL} INGRESS"
    assert "newly allows" in verdict.message
    assert "tcp/22" in verdict.message or "tcp/3389" in verdict.message
    # The witness must be a packet the old set really denied.
    assert witness_src(verdict.message) not in PRIVATE_10


@needs_z3
def test_a_narrowing_pair_is_grounded(snap):
    [verdict] = pair(load("fw_rule_baseline.json"), load("fw_rule_open.json"), snap)
    assert verdict.status == "grounded"
    assert verdict.kind == "firewall_pair"
    assert verdict.message.endswith("the new rule set allows no packet the old set denied")


@needs_z3
def test_an_identical_pair_is_grounded(snap):
    [verdict] = pair(load("fw_rule_open.json"), load("fw_rule_open.json"), snap)
    assert verdict.status == "grounded"


@needs_z3
def test_removing_an_egress_deny_is_a_widening(snap):
    # EGRESS carries an implied allow-all at 65535, so dropping the deny that
    # was holding tcp/25 shut widens the packet set even though the new
    # document's only rule is an *allow*.
    old = rest(name="deny-smtp-egress", direction="EGRESS", sourceRanges=[],
               destinationRanges=["0.0.0.0/0"], priority=1000,
               denied=[{"IPProtocol": "tcp", "ports": ["25"]}])
    old.pop("allowed")
    new = rest(name="allow-https-egress", direction="EGRESS", sourceRanges=[],
               destinationRanges=["0.0.0.0/0"],
               allowed=[{"IPProtocol": "tcp", "ports": ["443"]}])

    [verdict] = pair(new, old, snap)
    assert verdict.status == "contradicted"
    assert verdict.kind == "firewall_pair"
    assert verdict.target == f"{CANONICAL} EGRESS"
    assert "tcp/25" in verdict.message


@needs_z3
def test_an_egress_pair_that_keeps_the_deny_is_grounded(snap):
    # The same shape with the deny retained: the implied default-allow is
    # handled on both sides, so nothing is newly allowed.
    old = rest(name="deny-smtp-egress", direction="EGRESS", sourceRanges=[],
               destinationRanges=["0.0.0.0/0"],
               denied=[{"IPProtocol": "tcp", "ports": ["25"]}])
    old.pop("allowed")
    [verdict] = pair(dict(old), old, snap)
    assert verdict.status == "grounded"


@needs_z3
@pytest.mark.parametrize("broken_side", ["new", "baseline"])
def test_an_unsupported_rule_anywhere_abstains_the_whole_group(snap, broken_side):
    # Dropping an old deny would fabricate a widening; dropping a new allow
    # would fabricate a proof of safety. Neither: the group is not compared.
    broken = rest(name="fw-broken", priority="high",
                  sourceRanges=["0.0.0.0/0"],
                  allowed=[{"IPProtocol": "tcp", "ports": ["22"]}])
    sound = load("fw_rule_baseline.json")
    new, old = (broken, sound) if broken_side == "new" else (sound, broken)

    verdicts = pair(new, old, snap)
    assert [v.status for v in verdicts] == ["unverified"]
    assert not any(v.status == "contradicted" for v in verdicts)
    message = verdicts[0].message
    assert "fw-broken" in message and "priority" in message
    assert "fabricate" in message


@needs_z3
def test_a_baseline_on_a_different_network_is_not_compared(snap):
    new = load("fw_rule_open.json")
    old = rest(name="fw-other-net", network=OTHER_LINK,
               sourceRanges=["0.0.0.0/0"],
               allowed=[{"IPProtocol": "tcp", "ports": ["22"]}])
    [verdict] = pair(new, old, snap)
    assert verdict.status == "unverified"
    assert verdict.kind == "firewall_pair"
    assert "different network" in verdict.message
    assert "vpc-other" in verdict.message
    assert "no packet-set comparison was made" in verdict.message


@needs_z3
def test_a_non_firewall_baseline_is_not_compared(snap):
    # An empty "old" set would read every new allow as a widening.
    [verdict] = pair(load("fw_rule_open.json"), {"bindings": []}, snap)
    assert verdict.status == "unverified"
    assert "not a VPC firewall rule document" in verdict.message


@needs_z3
def test_a_rule_with_no_network_abstains_the_whole_comparison(snap):
    # Its group is unknowable, so it would silently empty whichever group it
    # really belonged to — an abstention for the pair, not for one group.
    broken = rest(name="fw-networkless", sourceRanges=["0.0.0.0/0"],
                  allowed=[{"IPProtocol": "tcp", "ports": ["22"]}])
    broken.pop("network")
    verdicts = pair(load("fw_rule_open.json"), broken, snap)
    assert [v.status for v in verdicts] == ["unverified"]
    assert "fw-networkless" in verdicts[0].message
    assert "could not be placed" in verdicts[0].message


@needs_z3
def test_a_group_present_on_only_one_side_still_participates(snap):
    # The new document adds an ingress rule to a network whose baseline rule is
    # egress: two groups, and the ingress one compares against the empty set.
    new = rest(name="allow-ssh-world", sourceRanges=["0.0.0.0/0"],
               allowed=[{"IPProtocol": "tcp", "ports": ["22"]}])
    old = rest(name="allow-https-egress", direction="EGRESS", sourceRanges=[],
               destinationRanges=["0.0.0.0/0"],
               allowed=[{"IPProtocol": "tcp", "ports": ["443"]}])
    verdicts = pair(new, old, snap)
    by_target = {v.target: v for v in verdicts}
    assert set(by_target) == {f"{CANONICAL} INGRESS", f"{CANONICAL} EGRESS"}
    # INGRESS: nothing on the old side, default deny-all -> the new allow widens.
    assert by_target[f"{CANONICAL} INGRESS"].status == "contradicted"
    # EGRESS: nothing on the new side, default allow-all on both -> no widening.
    assert by_target[f"{CANONICAL} EGRESS"].status == "grounded"


# ---------------------------------------------------------------------------
# The whole pipeline, when the document kind is routed here.
# ---------------------------------------------------------------------------


@pytest.mark.skipif("firewall_rule" not in preflight.DOCUMENT_KINDS,
                    reason="preflight does not route compute#firewall documents yet")
def test_ground_policy_routes_a_firewall_document_through_both_checks(snap):
    report = preflight.ground_policy(POLICIES / "fw_rule_open.json", snap,
                                     baseline=POLICIES / "fw_rule_baseline.json")
    kinds = {v.kind for v in report.verdicts}
    assert "firewall_exposure" in kinds
    assert "firewall_pair" in kinds
    if HAVE_Z3:
        assert report.ok is False
    else:
        assert report.ok is True
