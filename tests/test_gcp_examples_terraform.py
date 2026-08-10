"""The tracked terraform example behind the README's finale, pinned in-process.

``examples/terraform/`` is the demo's last step: ``base.tf.json`` is the clean
infrastructure (a byte-copy of the agentic tf corpus), ``terraform.tfstate`` is
its applied state (same corpus), and ``main.tf.json`` is the base plus EXACTLY
two violating blocks — a world-open tcp/22 ingress rule and a ``roles/owner``
grant to an outsider. This module pins three things:

* the FIXTURES themselves — the byte-copies really are byte-copies and the
  proposal really is base-plus-two-blocks, so the README's diff snippet cannot
  drift from the committed files;
* the GROUNDING — snapshot + terraform state + compiled requirements over the
  example DENIES, with ``firewall_exposure`` locating ``allow_ssh_world``, BOTH
  compiled promises contradicted — ``sec:vpc_firewall`` on the world-open rule
  and ``sec:iam`` on the owner grant — each refutation carrying the terraform
  block address an operator would edit, and the org-policy promise evaluating
  (it *holds*: ``no_sa_keys`` enforces key-creation disablement);
* the ``--proposal`` FLAG — the explicit spelling of the positional: identical
  output, config discovery rooted at the proposal file, a usage error when both
  spellings are given, today's usage error when neither is, fail-open refusal
  under ``--hook``, and the README's five-flag invocation itself exiting 1 with
  the narrative the README promises.

Everything is in-process (:func:`gcp_grounding.cli.main`, or the library route
through ``gate.terraform_proposal`` → ``engine.evaluate``): no subprocess is
spawned, so nothing here draws on the suite's spawn budget. Environment-honest
like the rest of the suite: without z3 neither the exposure check nor any
compiled promise can decide, so every denial pin is skipped rather than
vacuously branched.
"""

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from gcp_grounding import engine, gate, sec_rules, sources
from gcp_grounding.cli import main
from gcp_grounding.core.solver import get_solver

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
REPO_ROOT = Path(__file__).resolve().parent.parent

EXAMPLE = REPO_ROOT / "examples" / "terraform"
BASE = EXAMPLE / "base.tf.json"
PROPOSAL = EXAMPLE / "main.tf.json"
STATE = EXAMPLE / "terraform.tfstate"

#: The corpus the example's clean half is copied from, byte for byte.
TF_CORPUS = FIXTURES / "agentic" / "tf" / "base"

SNAPSHOT = FIXTURES / "agentic_snapshot.json"
#: The requirements corpus the README's step 1 compiles into ``demo/compiled``;
#: the tests compile it into a tmp dir instead — same artifacts, no reliance on
#: a generated directory the repo deliberately does not track.
SEC_CORPUS = FIXTURES / "sec_requirements"

PROMISE_ID = "no-open-ssh-rdp-ingress"
ADDRESS = "google_compute_firewall.allow_ssh_world"
IAM_PROMISE_ID = "no-primitive-roles-outside-domain"
IAM_ADDRESS = "google_project_iam_binding.contractor_owner"
ORG_PROMISE_ID = "sa-key-creation-disabled"

HAVE_Z3 = get_solver().backend == "z3"

#: Both violating blocks' checks and the DENIED pins need a solver: without z3
#: no promise compiles and the exposure check honestly degrades to unverified,
#: so the run does not deny. An explicit SKIP, never a bare return.
_needs_z3 = pytest.mark.skipif(
    not HAVE_Z3, reason="no z3: the exposure check and every compiled promise "
                        "abstain, so the example cannot deny")

#: The two blocks the proposal adds to the base — the same content the README's
#: diff snippet shows, pinned here so the snippet cannot drift from the file.
VIOLATING_FIREWALL = {
    "allow": [{"ports": ["22"], "protocol": "tcp"}],
    "direction": "INGRESS",
    "name": "allow-ssh-from-anywhere",
    "network": "projects/acme-prod/global/networks/prod-vpc",
    "priority": 800,
    "project": "acme-prod",
    "source_ranges": ["0.0.0.0/0"],
}
VIOLATING_BINDING = {
    "members": ["user:mallory@outsider.example"],
    "project": "acme-prod",
    "role": "roles/owner",
}


@pytest.fixture(autouse=True)
def _env_off(monkeypatch):
    """No test here inherits a developer's exported grounding configuration —
    every assertion is about what the NAMED flags do."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def compiled(tmp_path, capsys) -> Path:
    """The agentic requirements corpus, compiled like the README's step 1.

    Exit 1 is the corpus's own contract: it deliberately carries a
    booby-trapped document, and the artifacts — rejection record included —
    are still written.
    """
    out = tmp_path / "compiled"
    assert main(["compile-requirements", str(SEC_CORPUS), "--snapshot",
                 str(SNAPSHOT), "--out", str(out)]) == 1
    capsys.readouterr()
    return out


# -- the fixtures themselves ---------------------------------------------------


def test_the_example_is_the_base_corpus_plus_exactly_the_two_violating_blocks():
    assert BASE.read_bytes() == (TF_CORPUS / "main.tf.json").read_bytes(), (
        "base.tf.json must stay a byte-copy of the agentic tf corpus")
    assert STATE.read_bytes() == (TF_CORPUS / "terraform.tfstate").read_bytes(), (
        "terraform.tfstate must stay a byte-copy of the agentic tf corpus")
    expected = deepcopy(json.loads(BASE.read_text(encoding="utf-8")))
    expected["resource"]["google_compute_firewall"]["allow_ssh_world"] = \
        deepcopy(VIOLATING_FIREWALL)
    expected["resource"]["google_project_iam_binding"]["contractor_owner"] = \
        deepcopy(VIOLATING_BINDING)
    proposed = json.loads(PROPOSAL.read_text(encoding="utf-8"))
    assert proposed == expected, (
        "main.tf.json must be base.tf.json plus exactly the two violating "
        "blocks — nothing more, nothing less")


def test_the_example_ships_no_config_file():
    """The demo's point is the five explicit flags; the config-file spelling is
    prose, not a committed sibling that would silently reconfigure the run."""
    assert not (EXAMPLE / ".gcp-grounding.json").exists()


# -- the grounding, through the library route the CLI itself takes -------------


@_needs_z3
def test_the_example_grounds_denied_in_process(compiled):
    """Snapshot + terraform state + compiled requirements over the example:
    not ok, the exposure check locates ``allow_ssh_world``, BOTH violated
    promises are contradicted with their terraform blocks named, and the
    org-policy promise evaluates the terraform document (it holds)."""
    rules, carried = sec_rules.load_directory(str(compiled))
    assert rules, "the corpus must compile at least one enforcing promise"
    current = sources.load_current(sources.SourceOptions(
        primary=str(SNAPSHOT), terraform_state=(str(STATE),)))
    assert not current.problem, current.problem
    built = gate.terraform_proposal(str(PROPOSAL), raw=False)
    assert built.proposal is not None, built.note
    report = engine.evaluate(
        built.proposal, current,
        engine.RuleSet(compiled=tuple(rules), carry_verdicts=tuple(carried)),
    ).report
    assert not report.ok

    exposure = [v for v in report.verdicts
                if v.kind == "firewall_exposure" and v.status == "contradicted"]
    assert exposure, "the world-open tcp/22 rule must be a finding"
    assert any(ADDRESS in f"{v.target} {v.message}" for v in exposure), exposure

    promise = [v for v in report.verdicts
               if v.kind == "sec:vpc_firewall" and v.target == PROMISE_ID]
    assert len(promise) == 1, promise
    assert promise[0].status == "contradicted", promise[0]
    assert "refuted by proposed_firewall_rules[" in promise[0].message
    # The witness message names the BLOCK an operator must edit, not only the
    # flattened row that witnessed the violation.
    assert f"({ADDRESS})" in promise[0].message, promise[0].message

    # The SECOND violated promise: the owner grant refutes the IAM-domain
    # promise over the same terraform document, and its witness names the
    # binding block, the member and the role.
    grant = [v for v in report.verdicts
             if v.kind == "sec:iam" and v.target == IAM_PROMISE_ID]
    assert len(grant) == 1, grant
    assert grant[0].status == "contradicted", grant[0]
    assert "refuted by iam_bindings[" in grant[0].message
    assert f"({IAM_ADDRESS})" in grant[0].message, grant[0].message
    assert "member='user:mallory@outsider.example'" in grant[0].message
    assert "role='roles/owner'" in grant[0].message

    # And the org-policy promise EVALUATES the terraform document: no_sa_keys
    # enforces the constraint, so the promise holds instead of abstaining.
    org = [v for v in report.verdicts
           if v.kind == "sec:org_policy" and v.target == ORG_PROMISE_ID]
    assert len(org) == 1, org
    assert org[0].status == "grounded", org[0]

    # The closed caveat stays closed: no promise abstains for being handed a
    # terraform document instead of its own REST kind.
    stale = [v for v in report.verdicts
             if "not an IAM allow policy" in v.message
             or "not an Org Policy" in v.message]
    assert not stale, stale


# -- the --proposal flag -------------------------------------------------------


def test_the_proposal_flag_is_the_positional_spelled_explicitly(capsys):
    positional = invoke(capsys, "verify-policy", str(PROPOSAL),
                        "--snapshot", str(SNAPSHOT), "--no-config",
                        "--format", "json")
    explicit = invoke(capsys, "verify-policy", "--proposal", str(PROPOSAL),
                      "--snapshot", str(SNAPSHOT), "--no-config",
                      "--format", "json")
    assert positional == explicit, (
        "the two spellings must be indistinguishable end to end")


@_needs_z3
def test_the_proposal_flag_matches_the_positional_with_state_configured(
        compiled, capsys):
    argv = ("--snapshot", str(SNAPSHOT), "--terraform-state", str(STATE),
            "--requirements", str(compiled), "--no-config", "--format", "json")
    code_p, out_p, _ = invoke(capsys, "verify-policy", str(PROPOSAL), *argv)
    code_f, out_f, _ = invoke(capsys, "verify-policy",
                              "--proposal", str(PROPOSAL), *argv)
    assert code_p == code_f == 1
    # The verdicts — not the whole document, whose state block carries
    # wall-clock ages — must agree, modulo the one thing that varies BETWEEN
    # ANY two runs: z3 is free to mint a different witness IP for the exposure
    # check each time it is asked, so the minted dotted quad is normalized
    # before the comparison. Everything else must match exactly.
    import re

    def normalized(stdout: str) -> list[dict]:
        verdicts = json.loads(stdout)["verdicts"]
        for verdict in verdicts:
            verdict["message"] = re.sub(r"\(\d+\.\d+\.\d+\.\d+\)",
                                        "(a-minted-source)",
                                        verdict["message"])
        return verdicts

    assert normalized(out_p) == normalized(out_f)


def test_both_spellings_at_once_is_a_usage_error_naming_both(capsys):
    code, _, err = invoke(capsys, "verify-policy", str(PROPOSAL),
                          "--proposal", str(PROPOSAL),
                          "--snapshot", str(SNAPSHOT))
    assert code == 2
    assert "FILE" in err and "--proposal" in err


def test_neither_spelling_keeps_the_existing_usage_error(capsys):
    code, _, err = invoke(capsys, "verify-policy", "--snapshot", str(SNAPSHOT))
    assert code == 2
    assert "FILE is required" in err


def test_hook_mode_refuses_the_proposal_flag_fail_open(capsys, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    code, _, err = invoke(capsys, "verify-policy", "--hook",
                          "--proposal", str(PROPOSAL))
    assert code == 0, "a hook usage error must never block an edit"
    assert "--proposal" in err and "fail-open" in err


@_needs_z3
def test_config_discovery_is_rooted_at_the_proposal_file(tmp_path, capsys):
    """``--proposal`` participates in config discovery exactly as the
    positional does: a ``.gcp-grounding.json`` beside the proposal supplies the
    snapshot and the state, and the flag-spelled run still denies."""
    repo = tmp_path / "tfrepo"
    repo.mkdir()
    (repo / "main.tf.json").write_bytes(PROPOSAL.read_bytes())
    (repo / "terraform.tfstate").write_bytes(STATE.read_bytes())
    (repo / ".gcp-grounding.json").write_text(json.dumps({
        "schema": "gcp-grounding-config/1",
        "snapshot": str(SNAPSHOT),
        "terraform": {"state": "terraform.tfstate"},
    }), encoding="utf-8")
    code, out, _ = invoke(capsys, "verify-policy",
                          "--proposal", str(repo / "main.tf.json"))
    assert code == 1
    assert "FAILED" in out and ADDRESS in out


# -- the README's five-flag finale ---------------------------------------------


@_needs_z3
def test_the_readme_five_flag_invocation_denies_with_the_narrative(
        compiled, capsys):
    """The exact invocation the README's step 7 shows — every input named by
    its flag — exits 1, and the narrative tells the README's story: the
    proposal's resource list, DENIED on BOTH violated promises quoting their
    English sentences and naming their terraform blocks, the escalation
    warning, the honest widening abstention, and every promise domain
    evaluating the terraform document."""
    code, out, err = invoke(
        capsys, "verify-policy",
        "--proposal", str(PROPOSAL),
        "--snapshot", str(SNAPSHOT),
        "--terraform-state", str(STATE),
        "--requirements", str(compiled),
        "--explain")
    assert code == 1
    assert "FAILED" in out

    # WHAT WAS PROPOSED: the terraform kind with its resource count, one line
    # per resource address, blame nowhere in sight.
    assert "what was proposed:" in err
    assert "a terraform configuration (8 resources)" in err
    assert f"    {ADDRESS}" in err
    assert "    google_project_iam_binding.contractor_owner" in err

    # THE DECISION, with both findings.
    assert "decision: DENIED (exit 1)" in err
    assert "[firewall_exposure]" in err and ADDRESS in err
    assert f"({ADDRESS})" in err  # the refutation names the block

    # BOTH violated promises, each quoting its own sentence and naming the
    # terraform block an operator must edit.
    assert f"VIOLATED  {PROMISE_ID}" in err
    assert ("No ingress firewall rule may allow tcp/22 or tcp/3389 "
            "from 0.0.0.0/0.") in err
    assert f"VIOLATED  {IAM_PROMISE_ID}" in err
    assert ("No binding may grant roles/owner or roles/editor to any "
            "principal outside domain acme.example.") in err
    assert "refuted by iam_bindings[" in err
    assert f"({IAM_ADDRESS})" in err
    assert "member='user:mallory@outsider.example'" in err
    assert "role='roles/owner'" in err

    # The org-policy promise evaluates the terraform document and HOLDS —
    # no_sa_keys enforces the constraint the promise is scoped to.
    assert f"holds     {ORG_PROMISE_ID}" in err

    # The owner grant: escalation warning named on the binding, and the
    # widening note honestly unverified — terraform is never a complete
    # baseline, so new-versus-never-seen cannot be proven from it.
    assert "[iam_escalation]" in err and "contractor_owner" in err
    assert "roles/owner" in err and "user:mallory@outsider.example" in err
    assert "[subset]" in err and "new⊈old" in err
    assert "partial" in err

    # The old caveat is CLOSED: no promise reports "not an IAM allow policy" /
    # "not an Org Policy" for being handed a terraform document — every domain
    # evaluates it now, or abstains for a reason of its own.
    assert "not an IAM allow policy" not in err
    assert "not an Org Policy" not in err


def test_the_narrative_caps_the_resource_list_at_twenty_lines(tmp_path, capsys):
    """The terraform proposal block honours the existing 20-line cap with the
    elision count, exactly as the other document kinds do."""
    many = {"resource": {"google_compute_firewall": {
        f"rule_{i:02d}": {"name": f"rule-{i:02d}"} for i in range(25)}}}
    path = tmp_path / "many.tf.json"
    path.write_text(json.dumps(many), encoding="utf-8")
    _, _, err = invoke(capsys, "verify-policy", str(path),
                       "--snapshot", str(SNAPSHOT), "--no-config", "--explain")
    assert "a terraform configuration (25 resources)" in err
    listed = [line for line in err.splitlines()
              if line.startswith("    google_compute_firewall.rule_")]
    assert len(listed) == 20
    assert "    (... and 5 more)" in err
