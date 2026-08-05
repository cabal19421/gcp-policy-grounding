"""VPC firewall ESTATE tests: priority-ordered shadowing and re-opening of the
proposal against ``estate_snapshot.json``.

The centre of this file is the POLARITY PIN, asserted in BOTH directions for
both COVERAGE findings (A and C) so an inverted implementation — one that read
``unsat`` as "grounded", turning the check into a no-op with a green oracle —
cannot pass:

* FINDING A: the fully-shadowed allow tcp/22 at priority 1000 MUST produce a
  ``firewall_shadow`` verdict (asserted BY KIND, not merely by ``report.ok``
  being False: FINDING B could otherwise supply a failure for the wrong
  reason), and a genuinely live rule MUST produce an EMPTY list of
  ``firewall_shadow`` verdicts.
* FINDING C: the priority-700 blanket deny MUST kill ``allow-iap-ssh``, and a
  deny of tcp/3389 only — which leaves that rule's port-22 traffic alive —
  MUST NOT fire.

``vpc-main`` in the fixture carries deny-ssh-external at 900, allow-iap-ssh at
800, allow-internal at 1000 and allow-health-checks at 1000.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding import fw_estate, preflight, registry
from gcp_grounding.core.solver import get_solver
from gcp_grounding.fw_estate import check_firewall_shadowing
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import ground_policy
from gcp_grounding.registry import CheckContext
from gcp_grounding.tf_claims import terraform_plan_claims

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
NETWORK = "projects/acme-prod/global/networks/vpc-main"
FW_KINDS = ("firewall_shadow", "firewall_reopen")

HAVE_Z3 = get_solver().backend == "z3"
needs_z3 = pytest.mark.skipif(not HAVE_Z3, reason="the estate comparison needs z3")


@pytest.fixture(autouse=True)
def _fresh_registry():
    """Resolve the real PROVIDER_MODULES fresh, regardless of what a prior test
    module injected into the lazy provider cache."""
    registry.reset_cache()
    yield
    registry.reset_cache()


@pytest.fixture
def snap():
    return GcpSnapshot.load(FIXTURES / "estate_snapshot.json")


@pytest.fixture
def partial_snap():
    return GcpSnapshot.load(FIXTURES / "estate_partial_snapshot.json")


def plan(**values):
    """A ``terraform show -json`` plan proposing one google_compute_firewall."""
    values.setdefault("network", NETWORK)
    values.setdefault("direction", "INGRESS")
    values.setdefault("disabled", False)
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.5",
        "planned_values": {"root_module": {"resources": [{
            "address": "google_compute_firewall.proposed",
            "mode": "managed",
            "type": "google_compute_firewall",
            "name": "proposed",
            "provider_name": "registry.terraform.io/hashicorp/google",
            "values": values,
        }]}},
    }


def fw(report, kind=None, status=None):
    """The estate check's verdicts, optionally filtered by kind and status."""
    return [v for v in report.verdicts
            if v.kind in FW_KINDS
            and (kind is None or v.kind == kind)
            and (status is None or v.status == status)]


def context(doc, snapshot, solver=None):
    """A CheckContext exactly as ``ground_policy`` builds one, for the direct
    calls that must pin the check's own return value."""
    return CheckContext(snapshot=snapshot, solver=solver or get_solver(),
                        document=doc, document_kind="tf_plan", source="<plan>",
                        claims=tuple(terraform_plan_claims(doc)))


# -- the five acceptance documents --------------------------------------------

#: Fully shadowed: deny-ssh-external at 900 already decides every tcp/22 packet.
SHADOWED = plan(name="allow-ssh-world", priority=1000,
                source_ranges=["0.0.0.0/0"],
                allow=[{"protocol": "tcp", "ports": ["22"]}])

#: The same rule at priority 100, so it now wins over that deny.
REOPENING = plan(name="allow-ssh-world", priority=100,
                 source_ranges=["0.0.0.0/0"],
                 allow=[{"protocol": "tcp", "ports": ["22"]}])

#: The same again, restricted to RFC 1918 — a hole, but not an external one.
INTERNAL_ONLY = plan(name="allow-ssh-internal", priority=100,
                     source_ranges=["10.0.0.0/8"],
                     allow=[{"protocol": "tcp", "ports": ["22"]}])

#: A blanket deny above every existing allow.
BLANKET_DENY = plan(name="deny-all-tcp", priority=700,
                    source_ranges=["0.0.0.0/0"],
                    deny=[{"protocol": "tcp", "ports": ["0-65535"]}])

#: The same deny narrowed to RDP: allow-iap-ssh's port 22 survives it.
NARROW_DENY = plan(name="deny-rdp", priority=700, source_ranges=["0.0.0.0/0"],
                   deny=[{"protocol": "tcp", "ports": ["3389"]}])

#: A genuinely LIVE rule: it narrows the existing allow-internal (same name, so
#: the version being replaced is excluded from both partitions) to tcp/8080 and
#: moves it to priority 1100. Nothing above it matches that traffic —
#: deny-ssh-external and allow-iap-ssh are port 22 only, and allow-health-checks
#: reaches only tag:web instances over no protocol the snapshot recorded.
LIVE = plan(name="allow-internal", priority=1100, source_ranges=["10.0.0.0/8"],
            allow=[{"protocol": "tcp", "ports": ["8080"]}])

ALL_FIVE = (SHADOWED, REOPENING, INTERNAL_ONLY, BLANKET_DENY, LIVE)


# -- FINDING A: the polarity pin, both directions ------------------------------


@needs_z3
def test_fully_shadowed_allow_is_contradicted_firewall_shadow(snap):
    # Leg (i) of the pin, asserted BY KIND — `report.ok is False` alone would
    # also be satisfied by a FINDING B failure for the wrong reason.
    report = ground_policy(SHADOWED, snap)
    shadow = fw(report, kind="firewall_shadow")
    assert [v.status for v in shadow] == ["contradicted"]
    assert shadow[0].target == "allow-ssh-world"
    # The specific higher-precedence rule is named, not just "something".
    assert "deny-ssh-external" in shadow[0].message
    assert "unreachable" in shadow[0].message
    assert report.ok is False


@needs_z3
def test_live_rule_produces_zero_firewall_shadow_verdicts(snap):
    # Leg (ii): the empty list. An implementation that read `unsat` as
    # `grounded` would satisfy neither leg — it would report the dead rule
    # clean and flag this live one.
    report = ground_policy(LIVE, snap)
    assert fw(report, kind="firewall_shadow") == []
    assert fw(report) == []
    assert report.ok is True


@needs_z3
def test_partial_overlap_is_not_a_finding(snap):
    # tcp/20-25 from anywhere overlaps deny-ssh-external (tcp/22) but is not
    # covered by it: port 20 is still decided by this rule. Only FULL shadowing
    # fires; partial overlap is normal configuration.
    doc = plan(name="allow-ftp-range", priority=1000,
               source_ranges=["0.0.0.0/0"],
               allow=[{"protocol": "tcp", "ports": ["20-25"]}])
    assert fw(ground_policy(doc, snap), kind="firewall_shadow") == []


@needs_z3
def test_equal_rank_existing_rule_does_not_shadow(snap):
    # allow-internal sits at priority 1000 with action allow, exactly the rank
    # of this proposal — neither strictly higher nor strictly lower, so it is in
    # neither partition and cannot shadow.
    doc = plan(name="allow-internal-8080", priority=1000,
               source_ranges=["10.0.0.0/8"],
               allow=[{"protocol": "tcp", "ports": ["8080"]}])
    report = ground_policy(doc, snap)
    assert fw(report, kind="firewall_shadow") == []


@needs_z3
def test_a_differently_named_copy_at_1100_is_shadowed_by_allow_internal(snap):
    # The converse of LIVE, and why LIVE must be the same-name replacement: at
    # priority 1100 a *new* rule for tcp/8080 from 10.0.0.0/8 is fully covered
    # by allow-internal (tcp/0-65535 from 10.0.0.0/8 at 1000), which is then
    # named as the shadowing rule. Same-precedence arithmetic, opposite verdict.
    doc = plan(name="allow-app-8080", priority=1100,
               source_ranges=["10.0.0.0/8"],
               allow=[{"protocol": "tcp", "ports": ["8080"]}])
    [verdict] = fw(ground_policy(doc, snap), kind="firewall_shadow")
    assert verdict.status == "contradicted"
    assert "allow-internal" in verdict.message


# -- FINDING B: re-opening a higher-precedence deny -----------------------------


@needs_z3
def test_allow_below_a_deny_reopens_it_from_a_public_source(snap):
    report = ground_policy(REOPENING, snap)
    [verdict] = fw(report, kind="firewall_reopen")
    assert verdict.status == "contradicted"
    assert verdict.target == "allow-ssh-world"
    assert "deny-ssh-external" in verdict.message
    assert "priority 100" in verdict.message and "priority 900" in verdict.message
    # Family (a): sat IS the finding, so the model travels as the witness.
    assert "port 22" in verdict.message and "protocol 6" in verdict.message
    assert report.ok is False
    # And it is a re-opening, not a shadowing: nothing above it decides it.
    assert fw(report, kind="firewall_shadow") == []


@needs_z3
def test_internal_only_overlap_is_informational_and_does_not_fail_the_gate(snap):
    report = ground_policy(INTERNAL_ONLY, snap)
    [verdict] = fw(report, kind="firewall_reopen")
    assert verdict.status == "grounded"
    assert "internal ranges only" in verdict.message
    # The check_cel tautology-warning precedent: on the record, does not block.
    assert report.ok is True


# -- FINDING C: the polarity pin, both directions ------------------------------


@needs_z3
def test_blanket_deny_makes_an_existing_allow_unreachable(snap):
    report = ground_policy(BLANKET_DENY, snap)
    shadow = fw(report, kind="firewall_shadow")
    assert {v.status for v in shadow} == {"contradicted"}
    # Named by the EXISTING rule that died, not by the proposal.
    assert "allow-iap-ssh" in {v.target for v in shadow}
    killed = [v for v in shadow if v.target == "allow-iap-ssh"][0]
    assert "priority 700" in killed.message and "priority 800" in killed.message
    assert "unreachable" in killed.message
    assert report.ok is False


@needs_z3
def test_narrow_deny_leaves_the_existing_allow_alive(snap):
    # The negative leg: tcp/3389 does not cover allow-iap-ssh's tcp/22, so
    # nothing dies. allow-health-checks, whose captured layer4 is empty and so
    # matches no packet at all, was already dead in the estate and must not be
    # attributed to this proposal either.
    report = ground_policy(NARROW_DENY, snap)
    assert fw(report, kind="firewall_shadow") == []
    assert fw(report) == []
    assert report.ok is True


# -- abstention: the estate was not captured -----------------------------------


@needs_z3
@pytest.mark.parametrize("doc", ALL_FIVE)
def test_partial_snapshot_yields_only_unverified(doc, partial_snap):
    report = ground_policy(doc, partial_snap)
    verdicts = fw(report)
    assert [v.status for v in verdicts] == ["unverified"]
    assert "not captured" in verdicts[0].message
    assert "not decided" in verdicts[0].message
    # An uncaptured estate is never a pass-by-silence and never a block: THIS
    # channel abstains and nothing on it is a finding.
    #
    # `report.ok is True` held on the branch that wrote this, when the exposure
    # check did not exist. Two of these five docs open tcp/22 to 0.0.0.0/0, which
    # fw_checks.check_open_exposure legitimately contradicts — a finding about the
    # PROPOSAL, not about the uncaptured estate. So the report-wide claim is
    # pinned as: every finding in the report belongs to the exposure channel, and
    # the estate channel produced none.
    assert fw(report, status="ungrounded") == []
    assert fw(report, status="contradicted") == []
    findings = {v.kind for v in report.verdicts
                if v.status in ("ungrounded", "contradicted")}
    assert findings <= {"firewall_exposure", "firewall_reopen"}, findings


def test_builtin_backend_abstains_for_every_rule(snap, monkeypatch):
    # Every verdict the check itself returns is unverified, and the whole
    # report passes: no z3 means no decision, not a decision by default.
    builtin = get_solver(prefer="builtin")
    verdicts = check_firewall_shadowing(context(SHADOWED, snap, builtin))
    assert [v.status for v in verdicts] == ["unverified"]
    assert "z3 is not available" in verdicts[0].message

    monkeypatch.setattr(preflight, "get_solver", lambda: get_solver(prefer="builtin"))
    report = ground_policy(SHADOWED, snap)
    assert report.backend == "builtin"
    assert {v.status for v in fw(report)} == {"unverified"}
    assert report.ok is True


# -- abstention: shapes the encoding cannot represent --------------------------


def test_unsupported_payload_abstains_without_touching_the_solver(snap):
    # A rule with neither allow nor deny carries `unsupported`; it is never
    # dropped from the comparison, it abstains naming the reason.
    doc = plan(name="fw-empty", priority=1000, source_ranges=["0.0.0.0/0"])
    [verdict] = check_firewall_shadowing(context(doc, snap))
    assert verdict.status == "unverified"
    assert "not supported" in verdict.message
    assert "no allow or deny entry" in verdict.message


def test_uncanonicalizable_network_abstains(snap):
    # A bare network name cannot be matched against the estate's keys; reading
    # the resulting empty sweep as "nothing shadows this" would be a lie.
    doc = plan(name="fw-bare", network="vpc-main", priority=1000,
               source_ranges=["0.0.0.0/0"],
               allow=[{"protocol": "tcp", "ports": ["22"]}])
    [verdict] = check_firewall_shadowing(context(doc, snap))
    assert verdict.status == "unverified"
    assert "does not canonicalize" in verdict.message


@needs_z3
def test_an_unencodable_estate_rule_abstains_for_the_whole_comparison(snap):
    # An existing INGRESS rule with no source at all is a shape rule_match
    # refuses. Comparing against the rest would answer a different question, so
    # the whole comparison abstains — dropping an old deny would fabricate a
    # clean re-opening.
    data = json.loads((FIXTURES / "estate_snapshot.json").read_text(encoding="utf-8"))
    data["firewall_rules"]["projects/acme-prod/global/firewalls/deny-sourceless"] = {
        "network": NETWORK, "direction": "INGRESS", "action": "deny",
        "priority": 500, "layer4": [{"protocol": "tcp", "ports": ["22"]}],
    }
    broken = GcpSnapshot.from_dict(data)
    [verdict] = check_firewall_shadowing(context(SHADOWED, broken))
    assert verdict.status == "unverified"
    assert "could not be encoded" in verdict.message


@needs_z3
def test_a_solver_result_that_is_neither_sat_nor_unsat_abstains(snap, monkeypatch):
    class Stuck:
        def add(self, *_):
            pass

        def check(self):
            return "unknown"

    monkeypatch.setattr(fw_estate, "bounded_solver", lambda z3, **kw: Stuck())
    [verdict] = check_firewall_shadowing(context(SHADOWED, snap))
    assert verdict.status == "unverified"
    assert "unknown" in verdict.message


@needs_z3
def test_a_disabled_proposal_is_inert(snap):
    doc = plan(name="allow-ssh-world", priority=1000, disabled=True,
               source_ranges=["0.0.0.0/0"],
               allow=[{"protocol": "tcp", "ports": ["22"]}])
    assert check_firewall_shadowing(context(doc, snap)) == []


def test_a_document_with_no_firewall_claims_contributes_nothing(snap):
    doc = {"bindings": [{"role": "roles/viewer", "members": ["user:a@b.example"]}]}
    ctx = CheckContext(snapshot=snap, solver=get_solver(), document=doc,
                       document_kind="iam_policy", source="<policy>", claims=())
    assert check_firewall_shadowing(ctx) == []


# -- wiring --------------------------------------------------------------------


def test_the_check_is_registered_as_a_document_check():
    assert check_firewall_shadowing in registry.document_checks()
    assert fw_estate.DOCUMENT_CHECKS == (check_firewall_shadowing,)
