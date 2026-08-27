"""Agentic honesty for the effective org-policy fold, at the hook boundary.

Every case is one scripted :class:`~tests.agentic.fake_agent.Proposal` applied
by a :class:`~tests.agentic.fake_agent.FakeAgent` and pushed through
``gcp-ground verify-policy --hook`` — a real child process, a real PostToolUse
event, the real exit code and stderr — the tests/test_gcp_agentic_orgpolicy.py
pattern.  The committed corpus lives under
``tests/fixtures/gcp/agentic/orgeffective/`` and grounds against the dedicated
estate ``tests/fixtures/gcp/snapshot_orgeffective_estate.json`` (org →
folder → two projects; the key-creation guardrail enforced at the org with a
captured default of ALLOW; one estate rule carrying a resource-tag condition).

What the catalogue proves, per the design:

* THE FOLD CATCHES WHAT PER-DOCUMENT READING CANNOT — a project-level
  ``enforce: false`` under an enforcing org, and a folder-level ``reset``
  whose disablement only materialises at the projects below it, are both
  BLOCKED by the compiled effective-state promise, with the effective-state
  witness naming the row (z3 worlds; the no-z3 world abstains loudly instead,
  the documented builtin behaviour);
* UNCAPTURED ESTATE → the disablement proposal ABSTAINS loudly (never a
  pass), for ``org_policies`` and ``resource_hierarchy`` alike;
* a CONDITIONAL rule in the captured chain, and an UNDECIDABLE NODE (the
  name-after-apply plan), each abstain naming the node/rule or the block;
* an INERT proposal passes AND the ``org_effective`` inert finding is on the
  record; the BLAST-RADIUS finding lists exactly the changed nodes;
* the promise artifact is a REAL committed-shape ``*.promises.json`` written
  through :func:`gcp_grounding.sec_artifact.dumps` and loaded by the child
  through ``--requirements`` — the same admission path an operator's artifact
  takes.

**Spawns, MEASURED:** eight hook children in a full run (each sidecar report
is the in-process CLI mirror, the tests/test_gcp_agentic_secreq.py precedent,
so it costs nothing), pinned by :data:`MODULE_SPAWN_CAP` at module teardown.
The suite-wide ceiling moved 478 → 488 by exactly this module's declared cap
(8 measured plus two of headroom — the tx-agentic precedent).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
from unittest import mock

import pytest

from gcp_grounding import cli, sec_artifact, sec_ast, sec_encode, sec_probes
from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.solver import get_solver
from tests.agentic import env
from tests.agentic.asserts import (
    assert_abstained,
    assert_blocked,
    assert_no_verdictless_pass,
    assert_passed,
    assert_recorded,
)
from tests.agentic.fake_agent import FakeAgent, Proposal
from tests.agentic.hookrunner import (
    SCRUBBED_ENV,
    HookOutcome,
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    run_hook,
    scrub_stderr,
)

_SOLVER = get_solver()
Z3 = _z3_module(_SOLVER)
HAVE_Z3 = _SOLVER.backend == "z3"

#: Where the reviewable payload documents live.
ORGEFFECTIVE = env.AGENTIC / "orgeffective"

#: The dedicated estate this catalogue grounds against.
ESTATE = env.FIXTURES / "snapshot_orgeffective_estate.json"

#: Ceiling on the children THIS module spawns, checked at module teardown:
#: eight hook children measured, plus two of headroom.
MODULE_SPAWN_CAP = 10

KEYS = "iam.disableServiceAccountKeyCreation"
SHIELDED = "compute.requireShieldedVm"
EXTERNAL_IP = "compute.vmExternalIpAccess"
PROMISE_ID = "sa-key-creation-stays-effectively-enforced"


def payload(name: str) -> dict:
    return json.loads((ORGEFFECTIVE / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module", autouse=True)
def _module_spawn_cap(subprocess_budget):
    """Pin this module's share of the suite-wide spawn budget."""
    before = subprocess_budget.total
    yield
    spent = subprocess_budget.total - before
    assert spent <= MODULE_SPAWN_CAP, (
        f"this module spawned {spent} children, over its cap of "
        f"{MODULE_SPAWN_CAP}; the oracle is the full test run and an "
        f"unbounded suite stops being run at all")


# -- the compiled effective-state promise --------------------------------------


def _fld(name):
    return {"node": "field", "var": "e", "field": name}


def _cmp(op, left, right):
    return {"node": "cmp", "op": op, "left": left, "right": right}


#: The design's §9 example promise, verbatim in spirit: refute "the
#: key-creation constraint is effectively unenforced at ANY node the proposal
#: determines".
PROMISE_AST = {
    "node": "exists", "var": "e", "collection": "effective_org_policy_bool",
    "body": {"node": "and", "args": [
        _cmp("eq", _fld("constraint"),
             {"node": "lit", "sort": "Str", "value": KEYS}),
        _cmp("eq", _fld("enforce"),
             {"node": "lit", "sort": "Bool", "value": False}),
    ]}}


@pytest.fixture(scope="module")
def requirements_dir(tmp_path_factory):
    """One committed-shape ``*.promises.json`` artifact, built through the
    real serializer so the child's admission path (sexpr one-form, witness
    re-classification) is the one an operator's artifact takes."""
    sec_ast._ensure_domains()
    if HAVE_Z3:
        formula, consts = sec_encode.symbolic(Z3, PROMISE_AST)
        obl = sec_probes.obligation(Z3, formula, "refute")
        positive, negative = sec_probes.mint(Z3, obl, consts)
        assert positive is not None and negative is not None
    else:
        positive = negative = {"placeholder": "x"}
    promise = sec_artifact.Promise(
        id=PROMISE_ID,
        source=sec_artifact.Source(
            file="orgeffective.md", line=3,
            text="the service-account key-creation guardrail stays "
                 "effectively enforced at every node this change governs"),
        domain="org_policy", mode="refute", state="estate", severity="high",
        vocabulary=(), ast=PROMISE_AST,
        sexpr=sec_ast.render_sexpr(PROMISE_AST),
        free_consts=tuple(sec_ast.free_consts(PROMISE_AST)),
        positive=sec_artifact.Witness(assignment=positive, origin="z3-model"),
        negative=sec_artifact.Witness(assignment=negative, origin="z3-model"),
        wellformedness=sec_artifact.Wellformedness(satisfiable=True,
                                                   non_tautological=True),
        status="compiled", reason="")
    doc = sec_artifact.PromiseDoc(source_doc="orgeffective.md",
                                  promises=(promise,))
    directory = tmp_path_factory.mktemp("orgeffective-requirements")
    (directory / "orgeffective.promises.json").write_text(
        sec_artifact.dumps(doc), encoding="utf-8")
    return directory


# -- driving one proposal ------------------------------------------------------


def drive(case_id: str, workdir, *, kind="org_policy", tool="Write",
          snapshot=ESTATE, requirements=None, rationale=""):
    """Apply the proposal with a FakeAgent, push the event through the real
    hook, and return ``(outcome, sidecar)`` — the sidecar the in-process CLI
    mirror, so a case costs exactly one child."""
    name = (f"{case_id}.plan.json" if case_id.endswith("_node")
            else f"{case_id}.policy.json")
    proposal = Proposal(id=case_id, kind=kind, tool_name=tool,
                        rel_path=name, payload=payload(name),
                        expect="pass", rationale=rationale or case_id)
    agent = FakeAgent(workdir, [proposal])
    applied, event = agent.turn()
    path = agent.file_path(applied)
    extra = ("--requirements", str(requirements)) if requirements else ()
    outcome = run_hook(event, snapshot=snapshot, extra_argv=extra)

    def sidecar() -> dict:
        return _report_of(path, snapshot=snapshot, requirements=requirements)

    return outcome, sidecar


def _report_of(path, *, snapshot, requirements=None) -> dict:
    """The abstain sidecar, IN PROCESS: :func:`gcp_grounding.cli.main` over
    the exact argv ``ground_json`` would spawn — free against the module cap
    (the tests/test_gcp_agentic_secreq.py precedent)."""
    out, err = io.StringIO(), io.StringIO()
    argv = ["verify-policy", str(path), "--snapshot", str(snapshot),
            "--format", "json"]
    with mock.patch.dict(os.environ, {}, clear=False):
        for name in SCRUBBED_ENV:
            os.environ.pop(name, None)
        os.environ["GCP_SEC_LLM"] = "0"
        if requirements is not None:
            os.environ["GCP_GROUNDING_REQUIREMENTS"] = str(requirements)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
    outcome = HookOutcome(exit_code=code, stdout=out.getvalue(),
                          stderr=scrub_stderr(err.getvalue()),
                          argv=("<in-process>", *argv),
                          stderr_raw=err.getvalue())
    assert outcome.exit_code in (0, 1), (
        f"expected exit 0 or 1 (a verdict), got {outcome.exit_code}\n{outcome}")
    return json.loads(outcome.stdout)


# -- the fold catches what per-document reading cannot -------------------------


def test_e01_disabling_at_the_project_under_an_enforcing_org(agent_workdir,
                                                             requirements_dir):
    """``enforce: false`` at the project, under an org that enforces: the
    effective-state promise refutes with the witness naming the row."""
    outcome, sidecar = drive("E01_disable_at_project", agent_workdir,
                             requirements=requirements_dir,
                             rationale="let the pipeline mint SA keys again")
    if not HAVE_Z3:
        assert_abstained(outcome, sidecar(), "z3 is not available")
        return
    assert_blocked(outcome, PROMISE_ID, "effective_org_policy_bool")
    verdict = assert_recorded(sidecar(), status="contradicted",
                              kind="sec:org_policy", target=PROMISE_ID)
    assert "enforce=False" in verdict["message"], verdict
    assert "projects/orgfx-prod" in verdict["message"], verdict


def test_e02_a_folder_reset_is_blocked_at_the_projects_below(agent_workdir,
                                                             requirements_dir):
    """The design's flagship case: a folder-level reset with a captured
    default of ALLOW — the disablement only materialises BELOW the folder,
    and only the fold can see it."""
    outcome, sidecar = drive("E02_reset_at_folder", agent_workdir,
                             requirements=requirements_dir,
                             rationale="reset to the inherited default")
    if not HAVE_Z3:
        assert_abstained(outcome, sidecar(), "z3 is not available")
        return
    assert_blocked(outcome, PROMISE_ID)
    verdict = assert_recorded(sidecar(), status="contradicted",
                              kind="sec:org_policy", target=PROMISE_ID)
    assert "enforce=False" in verdict["message"], verdict


# -- uncaptured estate: loud abstention, never a pass --------------------------


@pytest.mark.parametrize("category", ["org_policies", "resource_hierarchy"])
def test_uncaptured_estate_abstains_loudly(agent_workdir, tmp_path,
                                           requirements_dir, category):
    data = json.loads(ESTATE.read_text(encoding="utf-8"))
    data.pop(category)
    partial = tmp_path / f"estate_without_{category}.json"
    partial.write_text(json.dumps(data, indent=2, sort_keys=True),
                       encoding="utf-8")
    outcome, sidecar = drive("E01_disable_at_project", agent_workdir,
                             snapshot=partial,
                             requirements=requirements_dir,
                             rationale="disable over a keyhole view")
    report = sidecar()
    assert_abstained(outcome, report, f"did not capture {category}")
    assert_no_verdictless_pass(outcome, report)
    # the promise itself is among the abstainers, by name
    verdict = assert_recorded(report, status="unverified",
                              kind="sec:org_policy", target=PROMISE_ID)
    assert f"did not capture {category}" in verdict["message"], verdict


# -- conditions and undecidable nodes ------------------------------------------


def test_e04_a_conditional_rule_in_the_captured_chain_abstains(agent_workdir):
    """The estate's org-level rule for the shielded-VM constraint carries a
    resource-tag condition: the before/after fold is undecidable and says so,
    naming the node and the rule."""
    outcome, sidecar = drive("E04_conditional_chain", agent_workdir,
                             rationale="enforce shielded VMs at prod")
    report = sidecar()
    assert_abstained(outcome, report, "condition")
    verdict = assert_recorded(report, status="unverified",
                              kind="org_effective")
    assert "organizations/500" in verdict["message"], verdict
    assert "rules[0]" in verdict["message"], verdict


def test_e06_an_undecidable_node_abstains_naming_the_block(agent_workdir,
                                                           requirements_dir):
    """The name-after-apply plan variant: the org-policy block yields no
    constraint claim, and the census abstention names the block to fix."""
    outcome, sidecar = drive("E06_unknown_node", agent_workdir,
                             kind="tf_plan", tool="Edit",
                             requirements=requirements_dir,
                             rationale="the name resolves at apply time")
    report = sidecar()
    assert_abstained(outcome, report, "google_org_policy_policy.after_apply")
    verdict = assert_recorded(report, status="unverified",
                              kind="sec:org_policy", target=PROMISE_ID)
    assert "google_org_policy_policy.after_apply" in verdict["message"]


# -- the two findings ----------------------------------------------------------


def test_e03_an_inert_proposal_passes_with_the_inert_finding(agent_workdir,
                                                             requirements_dir):
    """The positive control: restating the org's own enforce is byte-silent
    at the boundary AND the inert ``org_effective`` finding is on the record
    — a guardrail that changes nothing is a signal reviewers need."""
    outcome, sidecar = drive("E03_inert_restate", agent_workdir,
                             requirements=requirements_dir,
                             rationale="re-assert the guardrail")
    assert_passed(outcome)
    report = sidecar()
    assert_no_verdictless_pass(outcome, report)
    verdict = assert_recorded(report, status="grounded", kind="org_effective")
    assert "INERT" in verdict["message"], verdict
    if HAVE_Z3:
        assert_recorded(report, status="grounded", kind="sec:org_policy",
                        target=PROMISE_ID)


def test_e05_the_blast_radius_names_exactly_the_changed_descendants(
        agent_workdir):
    """Allowing an external-IP value at the folder moves the effective state
    at the folder AND both projects below it (the captured default was
    deny-all) — the finding lists exactly those nodes."""
    outcome, sidecar = drive("E05_widen_external_ip", agent_workdir,
                             rationale="allow the bastion an external IP")
    assert outcome.exit_code == 0, str(outcome)
    report = sidecar()
    assert_no_verdictless_pass(outcome, report)
    verdict = assert_recorded(report, status="grounded", kind="org_effective")
    message = verdict["message"]
    assert "alters the effective state" in message
    for node in ("folders/510", "projects/orgfx-prod", "projects/orgfx-dr"):
        assert node in message, (node, message)
    assert "3 of the 3 node(s)" in message


# -- corpus hygiene ------------------------------------------------------------


def test_every_committed_fixture_is_replayed_by_a_case():
    on_disk = {path.name for path in ORGEFFECTIVE.iterdir() if path.is_file()}
    assert on_disk == {
        "E01_disable_at_project.policy.json",
        "E02_reset_at_folder.policy.json",
        "E03_inert_restate.policy.json",
        "E04_conditional_chain.policy.json",
        "E05_widen_external_ip.policy.json",
        "E06_unknown_node.plan.json",
    }
    for name in on_disk:
        assert isinstance(payload(name), dict)
