"""Acceptance tests for IAM v2 deny-policy grounding.

:mod:`gcp_grounding.iam_deny` is the extractor for the ``iam_deny_policy``
document kind that ``sx-detect-kind`` learned to recognize: ``README.md`` and
:mod:`gcp_grounding.claims` promised "allow/deny", but until now a deny policy
emitted zero claims — a silent pass on a real artifact. This suite pins the
extractor end-to-end through :func:`~gcp_grounding.preflight.ground_policy`.

MERGE-ORDER CONTRACT with ``sx-iam-escalation``, now RESOLVED: this task shipped
the EXTRACTOR only, and while the offline check for ``denied_permission`` did
not exist every such claim hit the registry catch-all and recorded an honest
"no offline check is wired" ``unverified``. ``sx-iam-escalation`` has since
landed :mod:`gcp_grounding.iam_checks`, so those claims are now DECIDED — the
catch-all count is pinned at zero and the real verdict is asserted in its place.
"Grounds fully" still means zero ``ungrounded``, zero ``contradicted``,
``report.ok`` True, and it is still deliberately NOT "zero unverified":
``denied_principal`` has no checker yet, and a "zero unverified" assertion would
be satisfiable by silently dropping the claims — the exact honesty hole this
task closes.

The z3-dependent CEL assertions (a satisfiable / dead denial window) are gated
on the z3 solver backend, mirroring ``tests/test_gcp_constraints.py``; without
z3 the window degrades to ``unverified``, which still keeps the good fixture's
``report.ok`` True.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding import registry
from gcp_grounding.constraints import _Undecidable, _grant_pairs
from gcp_grounding.core.solver import get_solver
from gcp_grounding.iam_deny import iam_deny_policy_claims
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import detect_kind, ground_policy

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
ESTATE = FIXTURES / "estate_snapshot.json"
GOOD = POLICIES / "iam_deny_good.json"
BAD = POLICIES / "iam_deny_bad.json"
ALLOW = POLICIES / "iam_policy_good.json"

HAS_Z3 = get_solver().backend == "z3"
needs_z3 = pytest.mark.skipif(not HAS_Z3, reason="z3 solver backend is not available")

GHOST = "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com"


@pytest.fixture()
def snapshot() -> GcpSnapshot:
    return GcpSnapshot.load(ESTATE)


@pytest.fixture(autouse=True)
def _fresh_registry():
    # ground_policy discovers iam_deny through the lazy provider registry; drop
    # any cache an earlier (possibly stub-injecting) test left behind.
    registry.reset_cache()
    yield
    registry.reset_cache()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# -- detection ----------------------------------------------------------------


def test_detect_kind_on_both_fixtures():
    assert detect_kind(_load(GOOD)) == "iam_deny_policy"
    assert detect_kind(_load(BAD)) == "iam_deny_policy"


# -- the good fixture grounds fully (in the pinned sense) ----------------------


def test_good_fixture_grounds_fully(snapshot):
    report = ground_policy(GOOD, snapshot)
    counts = report.counts()
    assert counts["ungrounded"] == 0
    assert counts["contradicted"] == 0
    assert report.ok is True
    # MERGE-ORDER, RESOLVED: `sx-iam-escalation` has landed, so
    # `gcp_grounding.iam_checks` now owns `denied_permission` and the catch-all
    # this suite used to count is gone — replaced by a real verdict naming the
    # escalation class the deny rule blocks. Still asserted by count, and still
    # deliberately NOT "zero unverified": `denied_principal` has no checker yet.
    catchall = [v for v in report.verdicts
                if v.kind == "denied_permission" and v.status == "unverified"
                and "no offline check is wired" in v.message]
    assert catchall == []
    decided = [v for v in report.verdicts
               if v.target == "iam.serviceAccountKeys.create"
               and "escalation path" in v.message]
    assert len(decided) == 1
    assert decided[0].status == "grounded"


def test_good_fixture_grounds_principals_and_normalized_permission(snapshot):
    report = ground_policy(GOOD, snapshot)
    grounded = {(v.kind, v.target) for v in report.verdicts if v.status == "grounded"}
    assert ("principal", "group:data-eng@acme.example") in grounded
    assert ("principal",
            "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com") in grounded
    # iam.googleapis.com/serviceAccountKeys.create → normalized iam.serviceAccountKeys.create
    assert ("permission", "iam.serviceAccountKeys.create") in grounded


@needs_z3
def test_good_fixture_denial_window_is_satisfiable(snapshot):
    report = ground_policy(GOOD, snapshot)
    cel = [v for v in report.verdicts if v.kind == "cel"]
    assert len(cel) == 1
    assert cel[0].status == "grounded"


# -- the bad fixture surfaces every planted defect ----------------------------


def test_bad_fixture_ghost_principal_is_ungrounded_with_suggestion(snapshot):
    report = ground_policy(BAD, snapshot)
    ghost = [v for v in report.ungrounded
             if v.kind == "principal" and v.target == GHOST]
    assert len(ghost) == 1
    assert ghost[0].suggestions  # a did-you-mean pointer at a real principal


def test_bad_fixture_misspelled_permission_is_ungrounded_with_suggestion(snapshot):
    report = ground_policy(BAD, snapshot)
    perm = [v for v in report.ungrounded
            if v.kind == "permission" and v.target == "iam.roles.updat"]
    assert len(perm) == 1
    assert "iam.roles.update" in perm[0].suggestions


@needs_z3
def test_bad_fixture_dead_window_is_contradicted(snapshot):
    report = ground_policy(BAD, snapshot)
    cel = [v for v in report.contradicted if v.kind == "cel"]
    assert len(cel) == 1
    assert "dead binding" in cel[0].message


# -- extractor-level shape guarantees -----------------------------------------


def test_wildcard_permission_yields_denied_permission_but_no_existence_claim():
    claims = iam_deny_policy_claims(
        {"rules": [{"denyRule": {"deniedPermissions": ["iam.googleapis.com/roles.*"]}}]})
    kinds = [c.kind for c in claims]
    assert "denied_permission" in kinds
    assert "permission" not in kinds  # a normalized name here would be a guess
    denied = [c for c in claims if c.kind == "denied_permission"]
    assert denied[0].value == "iam.googleapis.com/roles.*"


def test_public_principal_in_deniedPrincipals_carries_deny_polarity():
    claims = iam_deny_policy_claims(
        {"rules": [{"denyRule": {"deniedPrincipals": ["allUsers"]}}]})
    public = [c for c in claims if c.kind == "public_principal"]
    assert len(public) == 1
    assert public[0].value == "allUsers"
    assert public[0].fields()["polarity"] == "deny"
    # every deniedPrincipals entry also records a denied_principal for escalation
    assert any(c.kind == "denied_principal" and c.value == "allUsers" for c in claims)


def test_denied_principal_carries_rule_index():
    claims = iam_deny_policy_claims(
        {"rules": [{"denyRule": {"deniedPrincipals": ["group:data-eng@acme.example"]}}]})
    denied = [c for c in claims if c.kind == "denied_principal"]
    assert len(denied) == 1
    assert denied[0].fields()["rule_index"] == 0


def test_terraform_spelling_produces_identical_claims():
    expr = 'request.time < timestamp("2027-01-01T00:00:00Z")'
    rest = {"rules": [{"denyRule": {
        "deniedPrincipals": ["group:data-eng@acme.example"],
        "exceptionPrincipals":
            ["serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com"],
        "deniedPermissions": ["iam.googleapis.com/serviceAccountKeys.create"],
        "denialCondition": {"expression": expr}}}]}
    tf = {"rules": [{"deny_rule": {
        "denied_principals": ["group:data-eng@acme.example"],
        "exception_principals":
            ["serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com"],
        "denied_permissions": ["iam.googleapis.com/serviceAccountKeys.create"],
        "denial_condition": {"expression": expr}}}]}
    assert iam_deny_policy_claims(rest) == iam_deny_policy_claims(tf)


def test_document_name_yields_no_claim():
    # The deny policy is being created; its own name asserts nothing.
    claims = iam_deny_policy_claims(_load(GOOD))
    assert all(claim.value != _load(GOOD)["name"] for claim in claims)


# -- malformed shapes are conservatively skipped ------------------------------


@pytest.mark.parametrize("doc", [
    {"rules": ["not-an-object"]},
    {"rules": [{"denyRule": "not-an-object"}]},
    {"rules": [{"denyRule": {"deniedPrincipals": "not-a-list"}}]},
    {"rules": [{"denyRule": {"deniedPermissions": "not-a-list"}}]},
])
def test_malformed_shapes_yield_no_claims(doc):
    assert iam_deny_policy_claims(doc) == []


# -- baseline / subset contract -----------------------------------------------


def test_deny_policy_as_baseline_stays_unverified_subset(snapshot):
    report = ground_policy(ALLOW, snapshot, baseline=BAD)
    subset = [v for v in report.verdicts if v.kind == "subset"]
    assert len(subset) == 1
    assert subset[0].status == "unverified"


def test_grant_pairs_undecidable_on_deny_policy():
    # Unchanged confirmation: a deny policy's 'rules' access surface is genuinely
    # not a (role, member) grant set, so _grant_pairs must refuse it.
    with pytest.raises(_Undecidable):
        _grant_pairs(_load(GOOD), "new")
