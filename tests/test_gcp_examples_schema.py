"""Scenario four — the attribute the provider doesn't know — pinned in-process.

``examples/terraform-schema/`` is the README's fourth scenario:
``provider-schema.json`` is a captured ``terraform providers schema -json``
for the ``google`` provider, wrapped in the documented
``gcp-provider-schema/1`` envelope so the capture time is IN THE FILE (it
records no ``provider_versions``, so the provider version is still UNKNOWN and
no message may name one), ``proposal_ok.tf.json`` is a clean
change, ``proposal_typo.tf.json`` is the same change with ``src_ranges`` for
``source_ranges``, and ``proposal_newer.tf.json`` adds a ``params`` block the
captured schema does not define. This module pins:

* the FIXTURES — the typo proposal differs from the clean one by exactly the
  renamed key, the newer one by exactly the added block, and the schema
  fixture is the envelope around a raw terraform capture defining exactly the
  three resource types the proposals use — so the README's story cannot drift
  from the committed files;
* the CAPTURE STAMP and the CLOCK, together, because either alone rots: the
  envelope's ``captured_at`` is what the freshness ceiling reads (never the
  file's modification time, which every fresh clone resets and every tarball
  freezes at the commit), and the runs here pin ``GCP_GROUNDING_NOW`` to the
  era the README's own scenario-four commands pin. That pairing is what makes
  the documented DENIALS reproduce from ANY checkout on ANY date;
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

from gcp_grounding import discovery, freshness, provider_schema
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

#: The capture stamp the committed envelope records, and the clock the README's
#: scenario-four commands pin beside it — the demo estate's own era. Stated as
#: constants because the conformance test below is about exactly this pair.
SCHEMA_CAPTURED_AT = "2026-07-25T08:00:00Z"
PINNED_NOW = "2026-07-25T12:00:00Z"

#: The three resource types the proposals use — and the whole scenario schema.
TYPES = ("google_access_context_manager_service_perimeter",
         "google_compute_firewall", "google_compute_security_policy",
         "google_org_policy_policy", "google_project_iam_binding",
         "google_project_iam_custom_role")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """No test inherits a developer's exported grounding configuration — and
    the clock is the one the README's own commands pin, not the calendar.

    The pin is not a convenience: the committed schema records its capture time
    (a fixture-era instant), so a run judged at the wall clock demotes the
    scenario's findings to abstentions the moment the fixture is more than the
    ceiling old, which is exactly the reproducibility defect these pins guard.
    """
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GCP_GROUNDING_NOW", PINNED_NOW)
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


def test_the_schema_fixture_is_the_documented_envelope_around_a_raw_capture():
    """Re-pinned from "the demo fixture is the RAW capture": that shape WAS the
    defect. A raw capture records no capture time, so the freshness ceiling fell
    back to the file's modification time — "now" in a fresh clone, the commit's
    instant in a tarball or a week-old checkout — and the scenario's documented
    denials became abstentions on every copy but a freshly cloned one. The
    envelope puts the capture time in the file, where no checkout can move it;
    the raw payload inside it is unchanged and still records no provider
    version, so no message may name a release."""
    document = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert document["schema"] == provider_schema.WRAPPER_SCHEMA
    assert document["captured_at"] == SCHEMA_CAPTURED_AT
    assert provider_schema.RAW_MARKER in document["raw"]
    assert set(document) == {"schema", "captured_at", "raw"}, (
        "the envelope records the capture time and nothing else: a "
        "provider_versions map would put release numbers in the findings")
    schema, problems = provider_schema.load(str(SCHEMA))
    assert problems == ()
    assert schema.resource_types() == tuple(sorted(TYPES))
    # Raw payload: the provider version is recorded as unknown, never invented.
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


# -- the capture stamp, and why it may not be the checkout's ---------------------


def test_the_freshness_stamp_is_the_files_own_and_cannot_go_stale(tmp_path):
    """The conformance pin for scenario four's reproducibility: the ceiling must
    read the stamp the FILE records, never the modification time a checkout
    happens to carry, and that stamp must be fresh under the clock the README's
    commands pin. Break either half and rows 4 and 4b stop being DENIED — from a
    tarball, from a week-old checkout, or from every checkout once the wall clock
    has moved a week past the capture.
    """
    schema, problems = provider_schema.load(str(SCHEMA))
    assert problems == ()
    assert schema.stamp_source == "captured_at", (
        "a 'file mtime' stamp is the defect: it makes the demo's verdicts a "
        "property of the copy rather than of the capture")
    assert schema.stamp == freshness.parse_timestamp(SCHEMA_CAPTURED_AT)
    # Fresh under the arc's pinned clock, with the whole ceiling to spare.
    assert provider_schema.staleness(
        schema, provider_schema.Runtime(paths=(str(SCHEMA),),
                                       now=PINNED_NOW)) == ""

    # The same file, copied with a modification time from far outside the
    # ceiling: the stamp does not move, so neither does the answer.
    copied = tmp_path / "provider-schema.json"
    copied.write_bytes(SCHEMA.read_bytes())
    ancient = freshness.parse_timestamp("2026-01-01T00:00:00Z").timestamp()
    os.utime(copied, (ancient, ancient))
    provider_schema.reset_cache()
    aged, problems = provider_schema.load(str(copied))
    assert problems == ()
    assert aged.stamp_source == "captured_at"
    assert aged.stamp == schema.stamp
    assert provider_schema.staleness(
        aged, provider_schema.Runtime(paths=(str(copied),),
                                      now=PINNED_NOW)) == ""


def test_10a_denies_from_a_checkout_whose_mtimes_are_the_commits(capsys,
                                                                tmp_path):
    """The regression, end to end: a tarball export, a ``git archive`` copy or a
    week-old checkout carries the COMMIT's modification times, and the documented
    ``✗ [tf_attribute]`` denial has to survive it whole — no ``[tf_schema]``
    staleness note, no demotion to an abstention, exit 1."""
    copied = tmp_path / "provider-schema.json"
    copied.write_bytes(SCHEMA.read_bytes())
    old = freshness.parse_timestamp("2026-01-01T00:00:00Z").timestamp()
    os.utime(copied, (old, old))

    code, out, err = invoke(capsys, "verify-policy",
                            "--proposal", str(PROPOSAL_TYPO),
                            "--snapshot", str(SNAPSHOT),
                            "--provider-schema", str(copied),
                            "--explain")
    assert code == 1
    assert "✗ [tf_attribute]" in out
    assert "(did you mean: source_ranges?)" in out
    assert "[tf_schema]" not in out, (
        "the schema's age must be read off its own captured_at, so a copy's "
        "modification time cannot demote the finding to an abstention")
    assert "DENIED (exit 1)" in err[err.index("decision recap:"):]


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
    # The figure the README quotes for 10c, under the clock its command pins.
    assert "decision recap: APPROVED (exit 0) — grounded=8 unchecked=5" in err


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
