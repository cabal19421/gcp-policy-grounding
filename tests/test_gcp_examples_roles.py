"""Scenario two — the custom-role swap — pinned in-process.

``examples/terraform-roles/`` is the README's second scenario: ``base.tf.json``
grants the predefined ``roles/bigquery.dataViewer`` to one group,
``terraform.tfstate`` is that binding as current state, and each proposal swaps
the binding's role to a ``google_project_iam_custom_role`` defined in the same
document whose permissions are a strict subset of the predefined role's PLUS
exactly one extra — a harmless one in ``proposal_a.tf.json``
(``bigquery.jobs.create``), a promise-violating escalation-class one in
``proposal_b.tf.json`` (``iam.serviceAccounts.actAs``). This module pins four
things:

* the FIXTURES — the proposals differ from the base by exactly the role swap
  plus the custom-role block, from each other by exactly the one extra
  permission, and the state carries the same binding the base declares, so the
  README's story cannot drift from the committed files;
* the GROUNDING — case A approves (``ok=True``) with the ``iam_scope_diff``
  warning present naming the extra permission and the custom-role block; case B
  denies (``ok=False``) with the compiled promise contradicted and its witness
  naming the custom-role block;
* the EXTRACTOR for the new ``proposed_role_permissions`` collection — rows
  carry the role's full name, the permission and the block address; the
  conservative guards (count/for_each, unreadable shapes, the plan census, the
  honest no-REST-arm reason) each abstain by name;
* the CHECK — :func:`gcp_grounding.iam_scope.check_role_scope_diff` names
  extras over a plain (untainted) snapshot, abstains by name on everything it
  cannot prove, and stays silent for documents that do no swap.

Everything is in-process (no subprocess), and environment-honest: without z3 no
promise compiles and the denial pins are skipped rather than vacuously
branched. The grounding pins run through the same
``sources.load_current`` route the CLI takes; the fixture snapshot's
``captured_at`` (2026-07-25) is permanently past the default freshness limit,
so its categories are demoted and drift adjudication re-grades the scope-diff
warning to an abstention CARRYING THE SAME TEXT — which is why those pins
assert kind and message, and the plain-snapshot check tests below are where the
``grounded`` status itself is pinned.
"""

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from gcp_grounding import (baseline, drift, engine, gate, iam_scope, registry,
                           sec_ast, sec_domains, sec_rules, sources)
from gcp_grounding.cli import main
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.registry import CheckContext

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
REPO_ROOT = Path(__file__).resolve().parent.parent

EXAMPLE = REPO_ROOT / "examples" / "terraform-roles"
BASE = EXAMPLE / "base.tf.json"
PROPOSAL_A = EXAMPLE / "proposal_a.tf.json"
PROPOSAL_B = EXAMPLE / "proposal_b.tf.json"
STATE = EXAMPLE / "terraform.tfstate"

SNAPSHOT = FIXTURES / "agentic_snapshot.json"

PROMISE_ID = "no-actas-in-custom-roles"
SENTENCE = "No role may include the permission iam.serviceAccounts.actAs."
BINDING_ADDRESS = "google_project_iam_binding.analysts"
CUSTOM_ADDRESS = "google_project_iam_custom_role.data_viewer_scoped"
OLD_ROLE = "roles/bigquery.dataViewer"
NEW_ROLE = "projects/acme-prod/roles/dataViewerScoped"
EXTRA_A = "bigquery.jobs.create"
EXTRA_B = "iam.serviceAccounts.actAs"

#: The predefined role's snapshot-enumerated permissions minus the one the
#: custom role drops — the strict subset both proposals share.
KEPT = ("bigquery.datasets.get", "bigquery.tables.get", "bigquery.tables.getData")

HAVE_Z3 = get_solver().backend == "z3"

_needs_z3 = pytest.mark.skipif(
    not HAVE_Z3, reason="no z3: no promise compiles, so the scenario cannot "
                        "deny or hold — nothing here is decidable")


@pytest.fixture(autouse=True)
def _env_off(monkeypatch):
    """No test here inherits a developer's exported grounding configuration."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def compiled(tmp_path, capsys) -> Path:
    """The scenario's own corpus, compiled like the README's step 8. Exit 0:
    unlike the demo corpus, nothing in it is deliberately rejected."""
    out = tmp_path / "compiled-roles"
    assert main(["compile-requirements", str(EXAMPLE), "--snapshot",
                 str(SNAPSHOT), "--out", str(out)]) == 0
    capsys.readouterr()
    return out


def _document(path: Path):
    built = gate.terraform_proposal(str(path), raw=False)
    assert built.proposal is not None, built.note
    return built.proposal.document


def _current():
    current = sources.load_current(sources.SourceOptions(
        primary=str(SNAPSHOT), terraform_state=(str(STATE),)))
    assert not current.problem, current.problem
    return current


def _evaluate(proposal: Path, compiled: Path):
    rules, carried = sec_rules.load_directory(str(compiled))
    assert rules, "the scenario corpus must compile its one enforcing promise"
    built = gate.terraform_proposal(str(proposal), raw=False)
    assert built.proposal is not None, built.note
    current = _current()
    report = engine.evaluate(
        built.proposal, current,
        engine.RuleSet(compiled=tuple(rules), carry_verdicts=tuple(carried)),
    ).report
    # The CLI's one finishing pass (cli._finish_report) re-grades the existence
    # verdicts the reasoner minted outside any check: the binding's role names
    # a custom role this very change creates, and an `ungrounded` for it over a
    # view whose roles no source enumerated completely is not a hallucination
    # finding. The library route must apply the same post-pass to pin the same
    # decision the README commands show.
    snapshot, _ledger = baseline.current_view(current)
    drift.postpass(report, snapshot)
    return report


# -- the fixtures themselves ---------------------------------------------------


def test_proposal_a_is_the_base_plus_exactly_the_swap_and_the_custom_role():
    expected = deepcopy(json.loads(BASE.read_text(encoding="utf-8")))
    expected["resource"]["google_project_iam_binding"]["analysts"]["role"] = \
        NEW_ROLE
    expected["resource"]["google_project_iam_custom_role"] = {
        "data_viewer_scoped": {
            "permissions": sorted((*KEPT, EXTRA_A)),
            "project": "acme-prod",
            "role_id": "dataViewerScoped",
            "title": "Acme Data Viewer (scoped)",
        }}
    proposed = json.loads(PROPOSAL_A.read_text(encoding="utf-8"))
    assert proposed == expected, (
        "proposal_a.tf.json must be base.tf.json plus exactly the role swap "
        "and the custom-role block — nothing more, nothing less")


def test_the_proposals_differ_by_exactly_the_one_extra_permission():
    a = json.loads(PROPOSAL_A.read_text(encoding="utf-8"))
    b = json.loads(PROPOSAL_B.read_text(encoding="utf-8"))
    perms_a = a["resource"]["google_project_iam_custom_role"][
        "data_viewer_scoped"].pop("permissions")
    perms_b = b["resource"]["google_project_iam_custom_role"][
        "data_viewer_scoped"].pop("permissions")
    assert a == b, "outside the permissions list the proposals must be identical"
    assert set(perms_a) ^ set(perms_b) == {EXTRA_A, EXTRA_B}
    assert set(perms_a) & set(perms_b) == set(KEPT)
    # ... and the shared subset really is a STRICT subset of the predefined
    # role's snapshot enumeration, which is what makes the diff decidable.
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    enumerated = set(snapshot["roles"][OLD_ROLE]["included_permissions"])
    assert set(KEPT) < enumerated
    assert EXTRA_A in set(snapshot["permissions"])
    assert EXTRA_B in set(snapshot["permissions"])
    assert EXTRA_A not in enumerated and EXTRA_B not in enumerated


def test_the_state_carries_the_same_binding_the_base_declares():
    declared = json.loads(BASE.read_text(encoding="utf-8"))[
        "resource"]["google_project_iam_binding"]["analysts"]
    state = json.loads(STATE.read_text(encoding="utf-8"))
    assert state["version"] == 4
    bindings = [r for r in state["resources"]
                if r["type"] == "google_project_iam_binding"]
    assert len(bindings) == 1 and bindings[0]["name"] == "analysts"
    attributes = bindings[0]["instances"][0]["attributes"]
    for key in ("role", "members", "project"):
        assert attributes[key] == declared[key], key


def test_the_example_ships_no_config_file():
    assert not (EXAMPLE / ".gcp-grounding.json").exists()


# -- the grounding, through the library route the CLI itself takes -------------


@_needs_z3
def test_case_a_grounds_ok_with_the_scope_diff_warning(compiled):
    report = _evaluate(PROPOSAL_A, compiled)
    assert report.ok, [v for v in report.verdicts
                       if v.status in ("contradicted", "ungrounded")]

    diff = [v for v in report.verdicts if v.kind == "iam_scope_diff"]
    assert len(diff) == 1, diff
    message = diff[0].message
    assert "warning" in message
    assert EXTRA_A in message, "the extra permission must be named"
    assert CUSTOM_ADDRESS in message, "the custom-role block must be named"
    assert OLD_ROLE in message and NEW_ROLE in message
    assert message.startswith(BINDING_ADDRESS)

    promise = [v for v in report.verdicts
               if v.kind == "sec:iam" and v.target == PROMISE_ID]
    assert len(promise) == 1, promise
    assert promise[0].status == "grounded", promise[0]


@_needs_z3
def test_case_b_grounds_denied_with_the_promise_naming_the_block(compiled):
    report = _evaluate(PROPOSAL_B, compiled)
    assert not report.ok

    promise = [v for v in report.verdicts
               if v.kind == "sec:iam" and v.target == PROMISE_ID]
    assert len(promise) == 1, promise
    assert promise[0].status == "contradicted", promise[0]
    assert "refuted by proposed_role_permissions[" in promise[0].message
    assert f"({CUSTOM_ADDRESS})" in promise[0].message
    assert f"permission={EXTRA_B!r}" in promise[0].message

    # The promise is the ONLY blocker: the swap warning itself never blocks.
    blocking = [v for v in report.verdicts
                if v.status in ("contradicted", "ungrounded")]
    assert blocking == promise, blocking

    diff = [v for v in report.verdicts if v.kind == "iam_scope_diff"]
    assert len(diff) == 1, diff
    assert f"{EXTRA_B} (impersonation)" in diff[0].message


# -- the README's step-8 invocations, five flags each ---------------------------


@_needs_z3
def test_the_readme_case_a_invocation_approves_with_the_warning_leading(
        compiled, capsys):
    code, out, err = invoke(
        capsys, "verify-policy",
        "--proposal", str(PROPOSAL_A),
        "--snapshot", str(SNAPSHOT),
        "--terraform-state", str(STATE),
        "--requirements", str(compiled),
        "--explain")
    assert code == 0
    assert "PASSED" in out
    assert "decision: APPROVED (exit 0)" in err
    # The warning-grade verdict appears in the report AND in the narrative's
    # decision block, where judgment kinds lead the abstention taste.
    assert "[iam_scope_diff]" in out and "[iam_scope_diff]" in err
    undecided = [line for line in err.splitlines()
                 if line.startswith("    ? [")]
    assert undecided and "[iam_scope_diff]" in undecided[0], undecided[:3]
    assert EXTRA_A in err and CUSTOM_ADDRESS in err
    assert f"holds     {PROMISE_ID}" in err


@_needs_z3
def test_the_readme_case_b_invocation_denies_with_the_narrative(
        compiled, capsys):
    code, out, err = invoke(
        capsys, "verify-policy",
        "--proposal", str(PROPOSAL_B),
        "--snapshot", str(SNAPSHOT),
        "--terraform-state", str(STATE),
        "--requirements", str(compiled),
        "--explain")
    assert code == 1
    assert "FAILED" in out
    assert "decision: DENIED (exit 1)" in err
    assert f"VIOLATED  {PROMISE_ID}" in err
    assert SENTENCE in err
    assert f"({CUSTOM_ADDRESS})" in err
    # The recap — the last lines a terminal shows — names the custom-role block.
    recap = err[err.index("decision recap:"):]
    assert "DENIED (exit 1)" in recap
    assert f"({CUSTOM_ADDRESS})" in recap
    assert f"permission={EXTRA_B!r}" in recap


# -- the proposed_role_permissions extractor ------------------------------------


def _extract(document, kind="tf_plan"):
    sec_domains.register()
    fn = sec_rules.EXTRACTORS["proposed_role_permissions"]
    ctx = sec_rules.RuleContext(snapshot=GcpSnapshot(captured_at="t"),
                                document=document, document_kind=kind,
                                source="test")
    return fn(ctx)


def test_the_collection_is_registered_proposal_tier_with_two_str_fields():
    sec_domains.register()
    spec = sec_ast.COLLECTIONS["proposed_role_permissions"]
    assert spec.tier == "proposal"
    assert spec.fields == {"role": "Str", "permission": "Str"}


def test_the_extractor_yields_one_addressed_row_per_permission():
    records, missing = _extract(_document(PROPOSAL_B))
    assert missing is None
    assert [r["permission"] for r in records] == sorted((*KEPT, EXTRA_B))
    assert {r["role"] for r in records} == {NEW_ROLE}
    assert {r[sec_rules.WITNESS_ADDRESS_FIELD] for r in records} == \
        {CUSTOM_ADDRESS}


def test_the_extractor_pins_the_no_rest_arm_honestly():
    records, missing = _extract({"bindings": []}, kind="iam_policy")
    assert records == ()
    assert "not a terraform plan" in missing
    assert "no supported REST document kind" in missing


def test_the_extractor_abstains_on_count_by_name():
    document = _document(PROPOSAL_A)
    resource = document["planned_values"]["root_module"]["resources"]
    block = next(r for r in resource if r["address"] == CUSTOM_ADDRESS)
    block["values"]["count"] = 2
    records, missing = _extract(document)
    assert records == ()
    assert "'count'" in missing and CUSTOM_ADDRESS in missing


def test_the_extractor_abstains_on_a_non_string_permission_entry_by_name():
    document = _document(PROPOSAL_A)
    resource = document["planned_values"]["root_module"]["resources"]
    block = next(r for r in resource if r["address"] == CUSTOM_ADDRESS)
    block["values"]["permissions"] = ["bigquery.tables.get", 7]
    records, missing = _extract(document)
    assert records == ()
    assert CUSTOM_ADDRESS in missing
    assert "not a list of plain permission names" in missing


def test_the_plan_census_abstains_for_a_role_that_yielded_no_claims():
    document = _document(PROPOSAL_A)
    resource = document["planned_values"]["root_module"]["resources"]
    block = next(r for r in resource if r["address"] == CUSTOM_ADDRESS)
    block["values"]["permissions"] = "oops"      # not a list: no claims at all
    records, missing = _extract(document)
    assert records == ()
    assert CUSTOM_ADDRESS in missing
    assert "yielded no permission claims" in missing


def test_a_plan_with_no_custom_role_abstains_over_no_record():
    records, missing = _extract(_document(BASE))
    assert records == ()
    assert "carries no custom role resources" in missing


def test_a_custom_role_with_an_observed_empty_list_is_not_called_unread():
    document = _document(PROPOSAL_A)
    resource = document["planned_values"]["root_module"]["resources"]
    block = next(r for r in resource if r["address"] == CUSTOM_ADDRESS)
    block["values"]["permissions"] = []
    records, missing = _extract(document)
    assert records == ()
    assert "none of them names a permission" in missing


# -- the scope-diff check, over a plain (untainted) snapshot --------------------

#: A minimal snapshot: the old role enumerated, the current binding captured.
_CHECK_SNAPSHOT = {
    "captured_at": "2026-01-01T00:00:00Z",
    "roles": {OLD_ROLE: {
        "included_permissions": [*KEPT, "bigquery.tables.list"],
        "stage": "GA", "title": "BigQuery Data Viewer"}},
    "permissions": [*KEPT, "bigquery.tables.list", EXTRA_A, EXTRA_B],
    "iam_bindings": {
        "//cloudresourcemanager.googleapis.com/projects/acme-prod": {
            "bindings": [{"role": OLD_ROLE, "condition": None,
                          "members": ["group:data-eng@acme.example"]}]}},
}


def _check(document, snapshot=None, kind="tf_plan"):
    snap = GcpSnapshot.from_dict(snapshot or _CHECK_SNAPSHOT)
    ctx = CheckContext(snapshot=snap, solver=get_solver(), document=document,
                       document_kind=kind, source="test", claims=())
    return [v for v in registry.run_document_checks(ctx)
            if v.kind == "iam_scope_diff"]


def test_the_check_is_registered_as_a_document_check():
    assert "gcp_grounding.iam_scope" in registry.PROVIDER_MODULES
    assert iam_scope.check_role_scope_diff in registry.document_checks()


def test_extras_are_named_on_a_grounded_warning():
    verdicts = _check(_document(PROPOSAL_B))
    assert len(verdicts) == 1, verdicts
    verdict = verdicts[0]
    assert verdict.status == "grounded", verdict
    assert "warning" in verdict.message
    assert f"{EXTRA_B} (impersonation)" in verdict.message
    assert CUSTOM_ADDRESS in verdict.message
    assert verdict.message.startswith(BINDING_ADDRESS)


def test_a_swap_that_adds_nothing_is_affirmed_as_a_reduction():
    document = _document(PROPOSAL_A)
    resource = document["planned_values"]["root_module"]["resources"]
    block = next(r for r in resource if r["address"] == CUSTOM_ADDRESS)
    block["values"]["permissions"] = list(KEPT)
    verdicts = _check(document)
    assert len(verdicts) == 1, verdicts
    assert verdicts[0].status == "grounded"
    assert "warning" not in verdicts[0].message
    assert "none added" in verdicts[0].message
    assert "1 of 4 permission(s) dropped" in verdicts[0].message


def test_an_unenumerated_previous_role_abstains_by_name():
    snapshot = deepcopy(_CHECK_SNAPSHOT)
    del snapshot["roles"][OLD_ROLE]
    snapshot["roles"]["roles/other"] = {"included_permissions": ["iam.roles.get"],
                                        "stage": "GA", "title": "x"}
    verdicts = _check(_document(PROPOSAL_A), snapshot)
    assert len(verdicts) == 1, verdicts
    assert verdicts[0].status == "unverified"
    assert OLD_ROLE in verdicts[0].message
    assert "not in the snapshot's role enumeration" in verdicts[0].message


def test_an_uncaptured_permission_set_abstains_by_name():
    snapshot = deepcopy(_CHECK_SNAPSHOT)
    snapshot["roles"][OLD_ROLE]["included_permissions"] = []
    verdicts = _check(_document(PROPOSAL_A), snapshot)
    assert len(verdicts) == 1, verdicts
    assert verdicts[0].status == "unverified"
    assert "cannot anchor a scope diff" in verdicts[0].message


def test_uncaptured_iam_bindings_abstain_by_name():
    snapshot = {k: v for k, v in _CHECK_SNAPSHOT.items() if k != "iam_bindings"}
    verdicts = _check(_document(PROPOSAL_A), snapshot)
    assert len(verdicts) == 1, verdicts
    assert verdicts[0].status == "unverified"
    assert "did not capture" in verdicts[0].message
    assert "iam_bindings" in verdicts[0].message


def test_an_ambiguous_predecessor_abstains_by_name():
    snapshot = deepcopy(_CHECK_SNAPSHOT)
    key = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
    snapshot["iam_bindings"][key]["bindings"].append(
        {"role": "roles/bigquery.dataEditor", "condition": None,
         "members": ["group:data-eng@acme.example"]})
    verdicts = _check(_document(PROPOSAL_A), snapshot)
    assert len(verdicts) == 1, verdicts
    assert verdicts[0].status == "unverified"
    assert "ambiguous" in verdicts[0].message


def test_documents_that_do_no_swap_are_silent():
    # No custom role at all.
    assert _check(_document(BASE)) == []
    # A custom role nothing binds (the binding keeps its predefined role).
    document = _document(PROPOSAL_A)
    resource = document["planned_values"]["root_module"]["resources"]
    binding = next(r for r in resource if r["address"] == BINDING_ADDRESS)
    binding["values"]["role"] = OLD_ROLE
    assert _check(document) == []
    # A REST document kind.
    assert _check({"bindings": []}, kind="iam_policy") == []


def test_a_binding_whose_role_was_stripped_abstains_rather_than_reads_as_no_swap():
    document = _document(PROPOSAL_A)
    resource = document["planned_values"]["root_module"]["resources"]
    binding = next(r for r in resource if r["address"] == BINDING_ADDRESS)
    del binding["values"]["role"]
    verdicts = _check(document)
    assert len(verdicts) == 1, verdicts
    assert verdicts[0].status == "unverified"
    assert BINDING_ADDRESS in verdicts[0].message
    assert "was not decided" in verdicts[0].message
