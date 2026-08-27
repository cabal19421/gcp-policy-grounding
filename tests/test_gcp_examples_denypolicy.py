"""Scenario six — the deny that guarded the estate — pinned in-process.

``examples/terraform-denypolicy/`` is the README's sixth scenario: a payments
estate whose only real protection for token minting is an IAM deny policy.
``snapshot.json`` is the captured estate — the ``guard-token-mint`` deny policy
attached at ``projects/acme-pay-prod`` (denying the two token-mint permissions
to ``principalSet://goog/public:all``), the DORMANT ``roles/iam.
serviceAccountTokenCreator`` grant it keeps inert, the org→folder→projects
hierarchy, and the org-level ``iam.disableServiceAccountKeyCreation`` policy
with the constraint's managed default (``constraint_default: ALLOW``)
captured. The proposals are RENDERED PLANS, deliberately: a deletion is
visible only in a plan's ``resource_changes`` (scenario three's honest sharp
edge, from the other side), and the estate-tier judgments here read the
snapshot's own captured categories. This module pins four things:

* the FIXTURES — each variant differs from the base plan by exactly the one
  stated edit, and the snapshot carries the estate the story needs (the deny
  rule covers every permission the dormant grant's role enumerates, which is
  what makes the grant fully inert), so the README's story cannot drift from
  the committed files;
* the GROUNDING, decided empirically and pinned as observed — the base is
  APPROVED with all three scenario promises holding beside the masked-grant
  warning and the inert org finding; the carve-out is DENIED by both deny
  promises with the escaping (principal, permission) quoted verbatim; the
  removal is DENIED by the ``iam_deny_shadow`` wake contradiction naming the
  woken grant (the promises abstain by name — a delete-only plan carries no
  planned deny values to judge); the folder reset is DENIED by the estate-tier
  promise refuted over ``effective_org_policy_bool``, naming the folder node
  and the block, with the blast-radius finding enumerating the three demoted
  nodes;
* the README's step-12 invocations — ``--proposal`` + ``--snapshot`` +
  ``--requirements`` + ``--explain``, no terraform state (the estate the
  scenario reasons about lives in the snapshot's record tables, and a stray
  tfstate beside the proposal would silently re-route the run onto the merged
  path whose coverage rules withhold the estate fold's existence licence);
* the CLOCK — the runs pin ``GCP_GROUNDING_NOW`` to the fixture era exactly as
  the README commands do, because the wake and fold judgments are estate reads
  a stale snapshot may not license: at wall clock the staleness ceiling
  demotes every captured category and the removal run's DENY honestly decays
  to abstention. The pin is the package's documented CI answer, not a trick.

The deny-shadow interaction and the effective fold are z3-free by design
(backend-identical); the PROMISE verdicts ride the solver, so every pin that
needs a ``holds``/``VIOLATED`` promise line is skipped without z3 rather than
vacuously branched. The removal run's pin runs on BOTH backends — its denial
rests on the interaction check alone.
"""

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from gcp_grounding import iam_deny
from gcp_grounding.cli import main
from gcp_grounding.core.solver import get_solver

REPO_ROOT = Path(__file__).resolve().parent.parent

EXAMPLE = REPO_ROOT / "examples" / "terraform-denypolicy"
BASE = EXAMPLE / "plan_base.json"
THREADING = EXAMPLE / "plan_threading.json"
REMOVAL = EXAMPLE / "plan_remove_deny.json"
RESET = EXAMPLE / "plan_reset_payments.json"
SNAPSHOT = EXAMPLE / "snapshot.json"
CORPUS = EXAMPLE / "requirements.md"

#: The README commands pin the clock to the fixture era; the suite-wide pin in
#: conftest is the same instant, restated here because THESE tests would decay
#: (the removal run's DENY becomes an abstention) under any other clock.
PINNED_NOW = "2026-07-18T12:00:00Z"

STRONG_PROMISE = "every-deny-covers-token-creation"
NO_THREADING_PROMISE = "no-principal-threads-the-guardrail"
EFFECTIVE_PROMISE = "sa-key-creation-stays-effectively-enforced"

DENY_ADDRESS = "google_iam_deny_policy.guard_token_mint"
GRANT_ADDRESS = "google_project_iam_binding.payroll_ci_token_creator"
RESET_ADDRESS = "google_org_policy_policy.payments_default_sweep"
RESTATE_ADDRESS = "google_org_policy_policy.sa_key_guard"

CI_SA = "serviceAccount:payroll-ci@acme-pay-prod.iam.gserviceaccount.com"
#: The carve-out, in the v2 spelling the deny policy itself uses.
EXCEPTION = ("principal://iam.googleapis.com/projects/-/serviceAccounts/"
             "payroll-ci@acme-pay-prod.iam.gserviceaccount.com")
TOKEN = "iam.serviceAccounts.getAccessToken"
FOLDER = "folders/665544332211"
CONSTRAINT = "iam.disableServiceAccountKeyCreation"

HAVE_Z3 = get_solver().backend == "z3"

_needs_z3 = pytest.mark.skipif(
    not HAVE_Z3, reason="no z3: the promise verdicts abstain honestly on the "
                        "builtin backend, so no holds/VIOLATED line can pin")


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _resources(plan: dict) -> list[dict]:
    return plan["planned_values"]["root_module"]["resources"]


@pytest.fixture(autouse=True)
def _pinned_env(monkeypatch):
    """No inherited grounding configuration, and the README's own clock pin."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GCP_GROUNDING_NOW", PINNED_NOW)


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


# -- the fixtures themselves ---------------------------------------------------


def test_the_threading_plan_is_the_base_plus_exactly_the_carve_out():
    expected = deepcopy(_load(BASE))
    rule = _resources(expected)[0]
    assert rule["address"] == DENY_ADDRESS
    rule["values"]["rules"][0]["deny_rule"][0][
        "exception_principals"] = [EXCEPTION]
    assert _load(THREADING) == expected, (
        "plan_threading.json must be plan_base.json plus exactly the one "
        "exception_principals entry on the guardrail's rule — nothing more, "
        "nothing less")


def test_the_removal_plan_deletes_exactly_the_guardrail_the_base_declares():
    """The delete-only rendered plan: empty planned values, one delete whose
    ``change.before`` is byte-for-byte the deny values the base plans — the
    old rules C3 computes the woken set from."""
    base_deny = _resources(_load(BASE))[0]
    removal = _load(REMOVAL)
    assert _resources(removal) == []
    changes = removal["resource_changes"]
    assert len(changes) == 1
    change = changes[0]
    assert change["address"] == DENY_ADDRESS
    assert change["change"]["actions"] == ["delete"]
    assert change["change"]["after"] is None
    assert change["change"]["before"] == base_deny["values"]


def test_the_reset_plan_is_the_base_plus_exactly_the_folder_reset():
    reset = _load(RESET)
    extra = [r for r in _resources(reset) if r["address"] == RESET_ADDRESS]
    assert len(extra) == 1, "the folder reset block must be present once"
    assert extra[0]["values"] == {
        "name": f"{FOLDER}/policies/{CONSTRAINT}",
        "parent": FOLDER,
        "spec": [{"reset": True}],
    }
    remaining = deepcopy(reset)
    _resources(remaining).remove(extra[0])
    assert remaining == _load(BASE), (
        "plan_reset_payments.json must be plan_base.json plus exactly the "
        "folder-reset block — nothing more, nothing less")


def test_the_snapshot_estate_matches_the_base_plan():
    """The story's premise as data: the applied estate the snapshot captured
    is what the base plan restates — the guardrail, the dormant grant, the
    org-level enforce — and the decidable managed default that makes the
    folder reset both judgeable and dangerous."""
    snapshot = _load(SNAPSHOT)
    assert snapshot["captured_at"] == "2026-07-18T09:00:00Z", \
        "the fixture era: fresh under the pinned clock"

    # The guardrail, as the estate table records it.
    (key, policy), = snapshot["iam_deny_policies"].items()
    assert key.endswith("/denypolicies/guard-token-mint")
    assert policy["attachment_point"] == "projects/acme-pay-prod"
    rule, = policy["rules"]
    plan_rule = _resources(_load(BASE))[0]["values"]["rules"][0][
        "deny_rule"][0]
    assert rule["denied_permissions"] == plan_rule["denied_permissions"]
    assert rule["denied_principals"] == plan_rule["denied_principals"]
    assert rule["exception_permissions"] == []
    assert rule["exception_principals"] == []

    # The dormant grant, matching the base plan's binding.
    bindings = snapshot["iam_bindings"][
        "//cloudresourcemanager.googleapis.com/projects/acme-pay-prod"][
        "bindings"]
    grant = [b for b in bindings
             if b["role"] == "roles/iam.serviceAccountTokenCreator"]
    assert grant == [{"members": [CI_SA],
                      "role": "roles/iam.serviceAccountTokenCreator"}]

    # The hierarchy chain the fold walks: org -> folder -> the two projects.
    hierarchy = snapshot["resource_hierarchy"]
    assert hierarchy[FOLDER]["parent"] == "organizations/123456789012"
    for project in ("projects/acme-pay-prod", "projects/acme-pay-dr"):
        assert hierarchy[project]["parent"] == FOLDER

    # The org-level enforce the reset silently undoes, and the captured
    # managed default that makes undoing it decidable.
    record = snapshot["org_policies"][
        f"organizations/123456789012|constraints/{CONSTRAINT}"]
    assert [r["enforce"] for r in record["rules"]] == [True]
    assert snapshot["constraints"][f"constraints/{CONSTRAINT}"][
        "constraint_default"] == "ALLOW"


def test_the_grant_is_fully_masked_by_the_guardrail():
    """Every permission the dormant grant's role enumerates is covered by the
    deny rule (on the normalized short form) — which is exactly why the base
    run's warning says 'the entire grant is inert' and why deleting the deny
    wakes an escalation-class pair."""
    snapshot = _load(SNAPSHOT)
    role = snapshot["roles"]["roles/iam.serviceAccountTokenCreator"]
    (_, policy), = snapshot["iam_deny_policies"].items()
    denied = {iam_deny._normalize_permission(p)
              for p in policy["rules"][0]["denied_permissions"]}
    assert None not in denied, "every denied permission must normalize"
    assert TOKEN in denied
    assert set(role["included_permissions"]) <= denied


def test_the_example_ships_no_config_state_or_sidecar():
    """The scenario's documented route is snapshot-only: a config file, a
    tfstate or an origins sidecar in this directory would be silently
    auto-discovered and re-route every README command onto the merged path."""
    assert not (EXAMPLE / ".gcp-grounding.json").exists()
    assert not list(EXAMPLE.glob("*.tfstate"))
    assert not list(EXAMPLE.glob("*.origins.json"))


def test_the_corpus_names_the_three_promises():
    text = CORPUS.read_text(encoding="utf-8")
    for promise_id in (STRONG_PROMISE, NO_THREADING_PROMISE,
                       EFFECTIVE_PROMISE):
        assert f"id: {promise_id}" in text
    assert "exists r in deny_rules" in text
    assert "exists e in deny_rule_exceptions" in text
    assert "exists e in effective_org_policy_bool" in text
    assert f'vocab: permission {TOKEN}' in text
    assert f"vocab: constraint constraints/{CONSTRAINT}" in text


# -- the README's step-12 invocations ------------------------------------------


@pytest.fixture
def compiled(tmp_path, capsys):
    """The scenario's own corpus, compiled like the README's step 12.
    Exit 0: nothing in it is booby-trapped."""
    out = tmp_path / "compiled-denypolicy"
    assert main(["compile-requirements", str(EXAMPLE), "--snapshot",
                 str(SNAPSHOT), "--out", str(out)]) == 0
    capsys.readouterr()
    return out


def _verify(capsys, proposal: Path, compiled) -> tuple[int, str, str]:
    return invoke(
        capsys, "verify-policy",
        "--proposal", str(proposal),
        "--snapshot", str(SNAPSHOT),
        "--requirements", str(compiled),
        "--explain")


@_needs_z3
def test_the_readme_base_invocation_approves_with_all_three_holding(
        compiled, capsys):
    """APPROVED, with the guardrail visible from three directions: every
    promise holds, the masked-grant warning names the inert grant, and the
    org restatement draws the INERT finding — a judgment, not silence."""
    code, out, err = _verify(capsys, BASE, compiled)
    assert code == 0
    assert "PASSED" in out
    assert "decision: APPROVED (exit 0)" in err
    for promise_id in (STRONG_PROMISE, NO_THREADING_PROMISE,
                       EFFECTIVE_PROMISE):
        assert f"holds     {promise_id}" in err
    assert "refuted by" not in err
    # The C1 masked warning: the deny and the grant in ONE plan.
    assert (f"rule 0 of {DENY_ADDRESS} masks {TOKEN} (impersonation)"
            in out)
    assert "the entire grant is inert" in out
    # The observed-empty attestation rides the refute-mode promise.
    assert ("every deny rule was read and none carries a principal "
            "exception") in out
    # The inert org finding: a restatement is loud, never silent.
    assert f"[org_effective] {RESTATE_ADDRESS}: this change is INERT" in out


@_needs_z3
def test_the_readme_threading_invocation_denies_naming_the_escape(
        compiled, capsys):
    """DENIED by both deny promises, and everything quoted is a constant of
    the document: the refutations and the interaction warning all name the
    carved-out principal and the permissions it now escapes."""
    code, out, err = _verify(capsys, THREADING, compiled)
    assert code == 1
    assert "FAILED" in out
    assert "decision: DENIED (exit 1)" in err
    assert f"VIOLATED  {STRONG_PROMISE}" in err
    assert f"VIOLATED  {NO_THREADING_PROMISE}" in err
    recap = err[err.index("decision recap:"):]
    assert "DENIED (exit 1)" in recap
    assert (f"{STRONG_PROMISE}: refuted by deny_rules[0] ({DENY_ADDRESS})"
            in recap)
    assert "has_principal_exceptions=True" in recap
    assert f"permission='{TOKEN}'" in recap
    assert (f"{NO_THREADING_PROMISE}: refuted by deny_rule_exceptions[0] "
            f"({DENY_ADDRESS}) exception_principal='{EXCEPTION}'" in recap)
    # The interaction check names the same escape from the grant's side.
    assert (f"this grant to {CI_SA} threads the exception '{EXCEPTION}'"
            in out)
    assert "the guardrail does not cover it; review the exception" in out


def test_the_readme_removal_invocation_denies_on_the_woken_grant(
        compiled, capsys):
    """DENIED on the interaction check ALONE — z3-free, so this pin runs on
    both backends. The promises abstain by name: a delete-only plan carries
    no planned deny values, and abstention never manufactures the block."""
    code, out, err = _verify(capsys, REMOVAL, compiled)
    assert code == 1
    assert "FAILED" in out
    assert "decision: DENIED (exit 1)" in err
    recap = err[err.index("decision recap:"):]
    assert "DENIED (exit 1)" in recap
    assert (f"[iam_deny_shadow] {DENY_ADDRESS}: removing or narrowing "
            f"rule 0 wakes the dormant grant of {TOKEN} (impersonation) "
            f"to {CI_SA}" in recap)
    assert ("the deny policy was the only thing keeping a known escalation "
            "path inert") in recap
    assert "refuted by" not in err, "the denial is the check's, not a promise's"
    assert (f"IAM deny policy '{DENY_ADDRESS}' has no planned values" in err)


@_needs_z3
def test_the_readme_reset_invocation_denies_over_the_effective_collection(
        compiled, capsys):
    """DENIED by the estate-tier promise: no document anywhere spells
    ``enforce false``, and the refutation still names the folder node and the
    reset block — the fold made the inheritance visible. The blast-radius
    finding enumerates the three demoted nodes, and the org restatement's
    inert finding stands untouched beside it."""
    code, out, err = _verify(capsys, RESET, compiled)
    assert code == 1
    assert "FAILED" in out
    assert "decision: DENIED (exit 1)" in err
    assert f"VIOLATED  {EFFECTIVE_PROMISE}" in err
    # The two deny promises still hold: the guardrail itself is untouched.
    assert f"holds     {STRONG_PROMISE}" in err
    assert f"holds     {NO_THREADING_PROMISE}" in err
    recap = err[err.index("decision recap:"):]
    assert (f"{EFFECTIVE_PROMISE}: refuted by effective_org_policy_bool[0] "
            f"({RESET_ADDRESS}) constraint='{CONSTRAINT}' enforce=False "
            f"node='{FOLDER}'" in recap)
    assert (f"[org_effective] {RESET_ADDRESS}: this change alters the "
            f"effective state of constraints/{CONSTRAINT} at 3 of the 3 "
            f"node(s) it governs" in out)
    for node in (FOLDER, "projects/acme-pay-dr", "projects/acme-pay-prod"):
        assert f"{node}: enforce true -> false" in out
    assert f"[org_effective] {RESTATE_ADDRESS}: this change is INERT" in out
