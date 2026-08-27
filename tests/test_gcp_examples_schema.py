"""Scenario four — the attribute the provider doesn't know — pinned in-process.

``examples/terraform-schema/`` is the README's fourth scenario:
``provider-schema.json`` is a captured ``terraform providers schema -json``
for the ``google`` provider (raw shape — so the provider version is honestly
UNKNOWN and no message may name one), ``proposal_ok.tf.json`` is a clean
change, ``proposal_typo.tf.json`` is the same change with ``src_ranges`` for
``source_ranges``, and ``proposal_newer.tf.json`` adds a ``params`` block the
captured schema does not define. This module pins:

* the FIXTURES — the typo proposal differs from the clean one by exactly the
  renamed key, the newer one by exactly the added block, and the schema
  fixture is the raw terraform shape defining exactly the three resource
  types the proposals use — so the README's story cannot drift from the
  committed files;
* the README COMMANDS, in-process — 10a DENIED with the did-you-mean, 10b
  DENIED with the recapture guidance, 10c APPROVED with the family silent,
  and 10d (no schema configured, policy explicit) exiting 0 with the honest
  abstention naming the count of unjudged blocks;
* HOOK MODE respecting the same resolved policy — the typo edit blocks (exit
  2) under the default ``block`` and is byte-silent exit 0 under
  ``annotate``, which is the hook-annotates-while-CI-blocks pattern;
* the CONFIG-FILE layer — a ``.gcp-grounding.json`` naming ``provider_schema``
  is discovered from the proposal's own directory and produces the same
  denial with zero flags.
"""

import json
import os
from pathlib import Path

import pytest

from gcp_grounding import discovery, provider_schema
from gcp_grounding.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "gcp"

EXAMPLE = REPO_ROOT / "examples" / "terraform-schema"
SCHEMA = EXAMPLE / "provider-schema.json"
PROPOSAL_OK = EXAMPLE / "proposal_ok.tf.json"
PROPOSAL_TYPO = EXAMPLE / "proposal_typo.tf.json"
PROPOSAL_NEWER = EXAMPLE / "proposal_newer.tf.json"
SNAPSHOT = FIXTURES / "agentic_snapshot.json"

FIREWALL_ADDRESS = "google_compute_firewall.allow_health_checks"

#: The three resource types the proposals use — and the whole scenario schema.
TYPES = ("google_access_context_manager_service_perimeter",
         "google_compute_firewall", "google_compute_security_policy",
         "google_org_policy_policy", "google_project_iam_binding",
         "google_project_iam_custom_role")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """No test inherits a developer's exported grounding configuration."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)
    provider_schema.reset_cache()
    yield
    provider_schema.reset_cache()


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


# -- the fixtures themselves ----------------------------------------------------


def test_the_typo_proposal_is_the_clean_one_with_exactly_the_renamed_key():
    expected = json.loads(PROPOSAL_OK.read_text(encoding="utf-8"))
    firewall = expected["resource"]["google_compute_firewall"][
        "allow_health_checks"]
    firewall["src_ranges"] = firewall.pop("source_ranges")
    proposed = json.loads(PROPOSAL_TYPO.read_text(encoding="utf-8"))
    assert proposed == expected, (
        "proposal_typo.tf.json must be proposal_ok.tf.json with source_ranges "
        "renamed to src_ranges — nothing more, nothing less")


def test_the_newer_proposal_is_the_clean_one_plus_exactly_the_params_block():
    expected = json.loads(PROPOSAL_OK.read_text(encoding="utf-8"))
    expected["resource"]["google_compute_firewall"]["allow_health_checks"][
        "params"] = {"resource_manager_tags":
                     {"tagKeys/281479612953454": "tagValues/281482091912447"}}
    proposed = json.loads(PROPOSAL_NEWER.read_text(encoding="utf-8"))
    assert proposed == expected, (
        "proposal_newer.tf.json must be proposal_ok.tf.json plus exactly the "
        "params block")


def test_the_schema_fixture_is_the_raw_terraform_shape_with_the_three_types():
    document = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert "schema" not in document, "the demo fixture is the RAW capture"
    assert provider_schema.RAW_MARKER in document
    schema, problems = provider_schema.load(str(SCHEMA))
    assert problems == ()
    assert schema.resource_types() == tuple(sorted(TYPES))
    # Raw capture: the provider version is honestly unknown, never invented.
    assert schema.version_label() == ""
    firewall = schema.blocks_for("google_compute_firewall")[
        "registry.terraform.io/hashicorp/google"]
    assert "source_ranges" in firewall["attributes"]
    assert "src_ranges" not in firewall["attributes"]
    assert "params" not in firewall["attributes"]
    assert "params" not in firewall["block_types"]
    assert "allow" in firewall["block_types"]


def test_every_name_the_clean_proposal_uses_exists_in_the_snapshot():
    """The clean run must approve for schema reasons, not because the estate
    pass abstained on made-up names."""
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    ok = json.loads(PROPOSAL_OK.read_text(encoding="utf-8"))["resource"]
    binding = ok["google_project_iam_binding"]["analysts"]
    assert binding["role"] in snapshot["roles"]
    assert binding["members"][0] in snapshot["principals"]
    custom = ok["google_project_iam_custom_role"]["usage_auditor"]
    assert set(custom["permissions"]) <= set(snapshot["permissions"])
    for rtype in TYPES:
        assert rtype in snapshot["resource_types"]


def test_the_example_ships_no_config_file():
    assert not (EXAMPLE / ".gcp-grounding.json").exists()


# -- the README's step-10 invocations, verbatim ----------------------------------


def _verify(capsys, proposal: Path, *extra: str) -> tuple[int, str, str]:
    return invoke(capsys, "verify-policy",
                  "--proposal", str(proposal),
                  "--snapshot", str(SNAPSHOT),
                  "--provider-schema", str(SCHEMA),
                  *extra)


def test_10a_the_typo_is_denied_with_the_did_you_mean(capsys):
    code, out, err = _verify(capsys, PROPOSAL_TYPO, "--explain")
    assert code == 1
    assert "FAILED" in out
    assert "✗ [tf_attribute]" in out
    assert "'src_ranges' is not an attribute or nested block of " \
           "google_compute_firewall" in out
    assert "(did you mean: source_ranges?)" in out
    assert FIREWALL_ADDRESS in out
    # The recap — the last lines a terminal shows — carries the finding.
    recap = err[err.index("decision recap:"):]
    assert "DENIED (exit 1)" in recap
    assert "'src_ranges'" in recap
    # The honest side-effect the README quotes: with source_ranges misspelled
    # the rule HAS no source filter, so exposure abstains on the illegal shape.
    assert "illegal GCP shape" in out


def test_10b_the_version_skew_is_denied_with_the_recapture_guidance(capsys):
    code, out, err = _verify(capsys, PROPOSAL_NEWER, "--explain")
    assert code == 1
    assert "✗ [tf_attribute]" in out
    assert "'params' is not an attribute or nested block" in out
    assert "did you mean" not in out, "nothing in the schema is close"
    assert "NEWER than the captured schema" in out
    assert provider_schema.CAPTURE_COMMAND in out
    recap = err[err.index("decision recap:"):]
    assert "DENIED (exit 1)" in recap
    assert "NEWER than the captured schema" in recap


def test_10c_the_clean_proposal_approves_with_the_family_silent(capsys):
    code, out, err = _verify(capsys, PROPOSAL_OK, "--explain")
    assert code == 0
    assert "PASSED" in out
    for kind in ("[tf_attribute]", "[tf_block]", "[tf_resource_type]",
                 "[tf_schema]"):
        assert kind not in out, (
            f"{kind} on the clean proposal — the family must be silent when "
            f"every attribute resolves")
    assert "decision recap: APPROVED (exit 0)" in err


def test_10d_no_schema_configured_abstains_honestly(capsys):
    code, out, _err = invoke(capsys, "verify-policy",
                             "--proposal", str(PROPOSAL_OK),
                             "--snapshot", str(SNAPSHOT),
                             "--schema-policy", "block")
    assert code == 0
    assert "PASSED" in out
    assert "? [tf_schema]" in out
    assert "NO provider schema is supplied" in out
    assert "3 google_* resource block(s) were NOT judged" in out
    assert provider_schema.CAPTURE_COMMAND in out


def test_annotate_reports_the_same_text_without_blocking(capsys):
    code, out, _err = _verify(capsys, PROPOSAL_TYPO,
                              "--schema-policy", "annotate")
    assert code == 0
    assert "PASSED" in out
    assert "? [tf_attribute]" in out
    assert "'src_ranges' is not an attribute" in out
    assert "schema-policy 'annotate'" in out


def test_the_settings_layer_is_reported_by_state_explain(capsys):
    """The flag that was given gets its own row with its origin; the policy
    nobody set is named on the block's one defaults line — still visible, not
    a row of its own."""
    _code, _out, err = _verify(capsys, PROPOSAL_OK, "--state-explain")
    assert f"  provider_schema = {SCHEMA} [cli]" in err
    [defaults] = [line for line in err.splitlines()
                  if "settings at defaults:" in line]
    assert "schema_policy" in defaults.split(": ", 1)[1].split(", ")


def test_a_bad_schema_policy_from_the_environment_is_a_usage_error(
        capsys, monkeypatch):
    monkeypatch.setenv(provider_schema.SCHEMA_POLICY_ENV, "blockk")
    code, _out, err = invoke(capsys, "verify-policy",
                             "--proposal", str(PROPOSAL_OK),
                             "--snapshot", str(SNAPSHOT),
                             "--provider-schema", str(SCHEMA))
    assert code == 2
    assert "'blockk'" in err
    assert "block" in err and "annotate" in err and "off" in err


# -- hook mode: the same policy, the agent's exit codes --------------------------


def _hook_event(path: Path) -> str:
    return json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": str(path)}})


def _run_hook(capsys, monkeypatch, path: Path, **env: str):
    import io
    import sys
    monkeypatch.setenv("GCP_GROUNDING_SNAPSHOT", str(SNAPSHOT))
    monkeypatch.setenv(provider_schema.PROVIDER_SCHEMA_ENV, str(SCHEMA))
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "stdin", io.StringIO(_hook_event(path)))
    return invoke(capsys, "verify-policy", "--hook")


def test_the_hook_blocks_the_typo_under_the_default_block_policy(
        capsys, monkeypatch):
    code, out, err = _run_hook(capsys, monkeypatch, PROPOSAL_TYPO)
    assert code == 2
    assert out == ""
    assert "'src_ranges'" in err
    assert "(did you mean: source_ranges?)" in err


def test_the_hook_is_byte_silent_under_annotate(capsys, monkeypatch):
    """The hook-annotates-while-CI-blocks pattern: the same finding rides as an
    `unverified`, which never blocks and is silent without --abstain-notes."""
    code, out, err = _run_hook(capsys, monkeypatch, PROPOSAL_TYPO,
                               GCP_GROUNDING_SCHEMA_POLICY="annotate")
    assert code == 0
    assert out == "" and err == ""


def test_the_hook_passes_the_clean_proposal_in_silence(capsys, monkeypatch):
    code, out, err = _run_hook(capsys, monkeypatch, PROPOSAL_OK)
    assert code == 0
    assert out == "" and err == ""


# -- the config-file layer, discovered from the proposal --------------------------


def test_the_config_layer_supplies_the_schema_with_zero_flags(
        capsys, tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    proposal = repo / "main.tf.json"
    proposal.write_text(PROPOSAL_TYPO.read_text(encoding="utf-8"),
                        encoding="utf-8")
    (repo / discovery.CONFIG_NAMES[0]).write_text(json.dumps({
        "schema": discovery.CONFIG_SCHEMA,
        "snapshot": str(SNAPSHOT),
        "provider_schema": str(SCHEMA),
    }), encoding="utf-8")
    code, out, err = invoke(capsys, "verify-policy", str(proposal),
                            "--state-explain")
    assert code == 1
    assert "✗ [tf_attribute]" in out
    assert "(did you mean: source_ranges?)" in out
    assert f"provider_schema = {SCHEMA} [config " in err
