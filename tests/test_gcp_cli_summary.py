"""The closing ``summary — what just happened:`` block of ``--explain``.

In-process like :mod:`tests.test_gcp_cli`, driving :func:`gcp_grounding.cli.
main` and reading stderr with ``capsys``; the one ``--hook`` run simulates its
PostToolUse event by monkeypatching ``sys.stdin``.

WHAT THIS MODULE IS ACTUALLY GUARDING. The section restates inputs the rest of
the narrative already printed, which makes it the one surface that can drift
into claiming something the run never did — a state file nobody read, a promise
nobody compiled, a schema nobody loaded, a census of blocks nobody parsed. So
the assertions here are mostly about the JOINS: every row's provenance label is
the layer that really supplied it, the promise counts are the ones the promises
block itself printed, the census counts the blocks the proposal block listed,
and a denial's promise ids and built-in kinds are never each other. The
ordering assertions matter for a second reason: the decision has to stay the
last thing on the terminal, and a block appended after the recap is exactly how
that gets lost.

The promises row carries that same burden one level deeper. Its ids are a block
now — one line each, with the AUTHOR'S OWN sentence under them — so the join to
assert is the sentence's: it is the text the compiled artifact stores, compared
here against the artifact itself, and an artifact that stored none leaves the id
alone rather than being handed English nobody wrote.

Environment-honest like its neighbours: without z3 no promise compiles and no
rule is admitted, so the enforcing/violated arms are SKIPPED there rather than
silently asserting over an empty rule set.
"""

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from gcp_grounding.cli import (REQUIREMENTS_ENV, SNAPSHOT_ENV,
                               _PROMISE_TEXT_CAP, _SUMMARY_BLOCK_CAP,
                               _promise_block_lines, _result_lines,
                               _summary_section_lines, main)
from gcp_grounding.core.report import GroundingReport, Verdict
from gcp_grounding.core.solver import get_solver
from gcp_grounding.discovery import CONFIG_SCHEMA
from gcp_grounding.sources import TF_STATE_ENV

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
EXAMPLES = REPO_ROOT / "examples"

SNAPSHOT = FIXTURES / "snapshot.json"
GOOD = POLICIES / "iam_policy_good.json"

AGENTIC = FIXTURES / "agentic"
AGENTIC_SNAPSHOT = FIXTURES / "agentic_snapshot.json"
AGENTIC_REQUIREMENTS = FIXTURES / "sec_requirements"
A10_POLICY = AGENTIC / "iam" / "A10_owner_to_external.policy.json"

TF_PROPOSAL = EXAMPLES / "terraform" / "main.tf.json"
TF_STATE = EXAMPLES / "terraform" / "terraform.tfstate"
SCHEMA_PROPOSAL = EXAMPLES / "terraform-schema" / "proposal_typo.tf.json"
SCHEMA_OK = EXAMPLES / "terraform-schema" / "proposal_ok.tf.json"
PROVIDER_SCHEMA = EXAMPLES / "terraform-schema" / "provider-schema.json"

HEADER = "summary — what just happened:"
RECAP = "decision recap:"

#: The words the post-build sweep removes from the documentation; the product's
#: own new output must not put fresh ones back.
_SWEPT_WORDS = ("honest", "honestly", "quietly", "simply")

HAVE_Z3 = get_solver().backend == "z3"
_needs_z3 = pytest.mark.skipif(
    not HAVE_Z3, reason="no solver: no promise compiles, so nothing enforces")


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def section(err: str) -> str:
    """The summary block alone — everything from its header to the end."""
    assert HEADER in err, "the explain run printed no summary section"
    return err[err.index(HEADER):]


def row(err: str, label: str) -> str:
    """One summary row's VALUE, by label. Raises when the row is missing, so a
    dropped row fails here rather than passing an ``in`` check vacuously."""
    for line in section(err).splitlines():
        stripped = line.strip()
        if stripped.startswith(label) and " : " in stripped:
            head, _sep, value = stripped.partition(" : ")
            if head.strip() == label:
                return value
    raise AssertionError(f"no {label!r} row in:\n{section(err)}")


@pytest.fixture(autouse=True)
def _configuration_off(monkeypatch):
    """No test here inherits a developer's exported configuration.

    Every assertion is about what a GIVEN configuration prints, and an ambient
    ``$GCP_GROUNDING_REQUIREMENTS`` or ``$GCP_GROUNDING_TF_STATE`` would turn
    the none-configured rows into configured ones and invert them.
    """
    for name in (REQUIREMENTS_ENV, SNAPSHOT_ENV, TF_STATE_ENV):
        monkeypatch.delenv(name, raising=False)


def compiled_requirements(tmp_path: Path) -> Path:
    """The agentic corpus compiled into a tmp directory.

    Exit 1 by design — the corpus carries a deliberately rejected promise — and
    the artifacts are still written, which is what the pickup reads.
    """
    out = tmp_path / "compiled"
    assert main(["compile-requirements", str(AGENTIC_REQUIREMENTS),
                 "--snapshot", str(AGENTIC_SNAPSHOT), "--out", str(out)]) == 1
    return out


# -- presence and ordering -----------------------------------------------------


def test_the_summary_closes_every_explain_run(capsys):
    """All five rows, once, under the header — and the result LAST, so the
    decision is still the final thing the terminal shows."""
    code, _out, err = invoke(capsys, "verify-policy", str(GOOD),
                             "--snapshot", str(SNAPSHOT), "--explain")
    assert code == 0
    block = section(err)
    assert err.count(HEADER) == 1
    labels = ["terraform state on disk", "promises in force", "provider",
              "proposed change", "result"]
    positions = [block.index(f"  {label}") for label in labels]
    assert positions == sorted(positions)
    assert block.rstrip().splitlines()[-1].strip().startswith("result")


def test_the_summary_follows_the_decision_recap(capsys):
    """After the recap, not before it: the recap is what a reader scrolls to,
    and a block printed ahead of it pushes it back up the terminal."""
    _code, _out, err = invoke(capsys, "verify-policy", str(GOOD),
                              "--snapshot", str(SNAPSHOT), "--explain")
    assert err.index("state used this run") < err.index(RECAP) < err.index(HEADER)


def test_the_summary_avoids_the_swept_words(capsys):
    """The new output strings carry none of the words the documentation sweep
    removes — the sweep must not be handed fresh product-output occurrences."""
    _code, _out, err = invoke(capsys, "verify-policy", str(GOOD),
                              "--snapshot", str(SNAPSHOT), "--explain")
    lowered = section(err).casefold()
    assert not [word for word in _SWEPT_WORDS if word in lowered]


# -- the provenance labels -----------------------------------------------------


def test_a_flag_supplied_input_reports_the_cli_layer(capsys):
    """``[cli]`` on the rows a flag supplied — the same ``[origin]`` spelling
    ``--state-explain`` prints, read off the one settings resolution."""
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(SCHEMA_PROPOSAL), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--provider-schema",
                              str(PROVIDER_SCHEMA), "--terraform-state",
                              str(TF_STATE), "--explain")
    assert row(err, "terraform state on disk") == f"{TF_STATE} [cli]"
    assert row(err, "provider").startswith(f"{PROVIDER_SCHEMA} [cli] — ")


def test_an_environment_supplied_input_reports_the_env_layer(capsys, monkeypatch):
    monkeypatch.setenv(TF_STATE_ENV, str(TF_STATE))
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(TF_PROPOSAL), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--explain")
    assert row(err, "terraform state on disk") == f"{TF_STATE} [env]"


def test_a_config_supplied_input_reports_the_file_that_supplied_it(
        capsys, tmp_path):
    """``[config <path>]`` — the config label carries the file, exactly as the
    settings block of ``--state-explain`` renders it."""
    config = tmp_path / ".gcp-grounding.json"
    config.write_text(json.dumps({
        "schema": CONFIG_SCHEMA,
        "terraform": {"state": str(TF_STATE)},
    }), encoding="utf-8")
    proposal = tmp_path / "main.tf.json"
    proposal.write_text(TF_PROPOSAL.read_text(encoding="utf-8"),
                        encoding="utf-8")
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(proposal), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--explain")
    assert row(err, "terraform state on disk") == f"{TF_STATE} [config {config}]"


def test_several_state_files_are_one_per_line(capsys):
    """Every summary row whose value is a LIST prints the list as a block: two
    configured state files are two lines under a row that counts them, not one
    comma-joined row a reader has to take apart."""
    other = EXAMPLES / "terraform-masked" / "terraform.tfstate"
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(TF_PROPOSAL), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--terraform-state",
                              str(TF_STATE), "--terraform-state", str(other),
                              "--explain")
    assert row(err, "terraform state on disk") == "2 files [cli]"
    lines = section(err).splitlines()
    start = lines.index("  terraform state on disk : 2 files [cli]")
    assert lines[start + 1:start + 3] == [f"      {TF_STATE}", f"      {other}"]


def test_several_schemas_are_one_per_line(capsys, tmp_path):
    """The provider row the same way, each schema keeping its own clause — the
    one that loaded and the one that did not."""
    broken = tmp_path / "provider-schema.json"
    broken.write_text("{not json", encoding="utf-8")
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(SCHEMA_PROPOSAL), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--provider-schema",
                              str(PROVIDER_SCHEMA), "--provider-schema",
                              str(broken), "--explain")
    captured = json.loads(PROVIDER_SCHEMA.read_text(encoding="utf-8"))
    types = len(captured["provider_schemas"]
                ["registry.terraform.io/hashicorp/google"]["resource_schemas"])
    assert row(err, "provider") == "2 schemas in force"
    lines = section(err).splitlines()
    start = lines.index("  provider                : 2 schemas in force")
    assert lines[start + 1:start + 3] == [
        f"      {PROVIDER_SCHEMA} [cli] — google, {types} resource types",
        f"      {broken} [cli] — could not be read, so resource shapes were "
        f"not checked"]


# -- nothing configured --------------------------------------------------------


def test_nothing_configured_says_so_plainly(capsys):
    """The three no-input answers, each naming the consequence rather than
    printing an empty column a reader would read as "checked and clean"."""
    _code, _out, err = invoke(capsys, "verify-policy", str(GOOD),
                              "--snapshot", str(SNAPSHOT), "--explain")
    assert row(err, "terraform state on disk") == "none configured"
    assert row(err, "promises in force") == "none loaded"
    assert row(err, "provider") == \
        "no schema configured — resource shapes not checked"


# -- the provider row ----------------------------------------------------------


def test_the_provider_row_names_the_captured_provider_and_its_types(capsys):
    """The captured provider and how many resource types it defines — read from
    the schema ``tf_schema_checks`` itself loads, never from the path alone."""
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(SCHEMA_PROPOSAL), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--provider-schema",
                              str(PROVIDER_SCHEMA), "--explain")
    captured = json.loads(PROVIDER_SCHEMA.read_text(encoding="utf-8"))
    types = len(captured["provider_schemas"]
                ["registry.terraform.io/hashicorp/google"]["resource_schemas"])
    assert row(err, "provider") == \
        f"{PROVIDER_SCHEMA} [cli] — google, {types} resource types"


def test_an_unreadable_schema_is_not_counted_as_one_in_force(capsys, tmp_path):
    """A path that will not load says so; it never becomes a provider name and
    a resource-type count nobody read."""
    broken = tmp_path / "provider-schema.json"
    broken.write_text("{not json", encoding="utf-8")
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(SCHEMA_PROPOSAL), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--provider-schema",
                              str(broken), "--explain")
    assert row(err, "provider") == (f"{broken} [cli] — could not be read, so "
                                    f"resource shapes were not checked")


# -- the proposed-change census ------------------------------------------------


def test_the_census_counts_the_blocks_the_run_graded(capsys):
    """Block count by resource type, over the SAME entries the proposal block
    listed — the census is a re-count of what was parsed, not a new parse of a
    file nobody read."""
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(TF_PROPOSAL), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--explain")
    value = row(err, "proposed change")
    assert value.startswith(f"{TF_PROPOSAL} — a terraform configuration "
                            f"(8 resources): ")
    assert "3 google_compute_firewall" in value
    assert "2 google_project_iam_binding" in value
    # The proposal block above listed one line per address; the census must add
    # up to the same eight, whatever it chose to elide.
    addresses = [line for line in err[:err.index(RECAP)].splitlines()
                 if line.startswith("    google_")]
    assert len(addresses) == 8


def test_a_plan_census_counts_the_blocks_the_extractor_read(capsys):
    """A rendered plan is censused over ``tf_claims._google_resources`` — the
    walk the claim extraction itself performs, ``planned_values`` first — so a
    plan carrying no ``resource_changes`` array is still counted."""
    plan = EXAMPLES / "terraform-denypolicy" / "plan_base.json"
    document = json.loads(plan.read_text(encoding="utf-8"))
    assert "resource_changes" not in document      # planned_values only
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal", str(plan),
                              "--snapshot",
                              str(EXAMPLES / "terraform-denypolicy" /
                                  "snapshot.json"), "--explain")
    value = row(err, "proposed change")
    assert value.startswith(f"{plan} — a terraform plan: ")
    assert "1 google_iam_deny_policy" in value
    assert "2 google_project_iam_binding" in value


def test_a_document_with_no_terraform_census_gets_its_kind_alone(capsys):
    """A non-terraform kind is named and NOT given a block census: there are no
    resource blocks to count, and inventing a count is the failure mode."""
    _code, _out, err = invoke(capsys, "verify-policy", str(GOOD),
                              "--snapshot", str(SNAPSHOT), "--explain")
    assert row(err, "proposed change") == f"{GOOD} — an IAM allow-policy"


def test_an_unreadable_proposal_costs_the_census_and_nothing_else(
        capsys, tmp_path):
    garbled = tmp_path / "garbled.json"
    garbled.write_bytes(b"\xff\xfe{\x00}")
    code, _out, err = invoke(capsys, "verify-policy", str(garbled),
                             "--snapshot", str(SNAPSHOT), "--explain")
    assert code == 0                      # unverified, not a crash
    assert "could not be" in row(err, "proposed change")
    assert row(err, "result").startswith("APPROVED")


# -- the proposed change, in English -------------------------------------------
#
# The sentences are read back off the rows the run's own proposal-tier
# collection extractors produced — the rows a refuted promise's witness message
# quotes. So the assertions here are about the JOIN in both directions: a
# sentence names a block the proposal block above listed, and a block whose rows
# the run never read gets no sentence claiming otherwise.


def sentences(err: str) -> list[str]:
    """The English lines under the ``proposed change`` row, indent stripped."""
    lines = section(err).splitlines()
    start = next(i for i, line in enumerate(lines)
                 if line.strip().startswith("proposed change"))
    out = []
    for line in lines[start + 1:]:
        if line.strip().startswith("result"):
            break
        out.append(line.strip())
    return out


def test_an_iam_binding_block_reads_as_the_grant_it_makes(capsys):
    """One line per binding block, naming the role, the members and the block —
    the same address the recap's findings use, so the two join by eye."""
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(TF_PROPOSAL), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--explain")
    assert ("google_project_iam_binding.contractor_owner: grants roles/owner "
            "to user:mallory@outsider.example") in sentences(err)


def test_a_firewall_block_reads_as_what_it_opens(capsys):
    """Direction, protocol/port, ranges and network — the fields the
    ``proposed_firewall_rules`` rows carry and nothing else. A deny rule opens
    nothing, and says so."""
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(TF_PROPOSAL), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--explain")
    said = sentences(err)
    assert ("google_compute_firewall.allow_ssh_world: opens INGRESS tcp/22 "
            "from 0.0.0.0/0 on projects/acme-prod/global/networks/prod-vpc"
            ) in said
    assert ("google_compute_firewall.deny_rdp: denies INGRESS tcp/3389 "
            "from 0.0.0.0/0 on projects/acme-prod/global/networks/prod-vpc"
            ) in said


def test_a_rest_policys_members_are_joined_and_its_condition_noted(capsys):
    """A REST allow policy has no block address to name, so its bindings are
    grouped by the role and condition its rows carry: the members of one binding
    join into one line, and a gated binding says when it applies."""
    _code, _out, err = invoke(capsys, "verify-policy", str(GOOD),
                              "--snapshot", str(SNAPSHOT), "--explain")
    said = sentences(err)
    assert ("grants roles/bigquery.dataViewer to group:data-eng@acme.example, "
            "user:alice@acme.example") in said
    gated = [line for line in said if "roles/storage.objectViewer" in line]
    assert gated == ['grants roles/storage.objectViewer to serviceAccount:'
                     'etl-runner@acme-prod.iam.gserviceaccount.com when '
                     'request.time < timestamp("2027-01-01T00:00:00Z")']


def test_a_deny_policy_names_its_permissions_principals_and_carve_outs(capsys):
    """Scenario 6a, end to end: what is denied, to whom, and who is exempted —
    the exemption read from the ``deny_rule_exceptions`` rows, joined to the
    rule by the same (block, rule index) the two collections share.

    The arc's plan carries planned values and no ``resource_changes``, so it
    states no change action and the guardrail reads as the creation it is: a
    "creates" here is the document's own silence about actions, never a guess
    about one. The same carve-out told by a plan that STATES the update reads as
    the delta instead (see the change-story block below).
    """
    plan = EXAMPLES / "terraform-denypolicy" / "plan_threading.json"
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal", str(plan),
                              "--snapshot",
                              str(EXAMPLES / "terraform-denypolicy" /
                                  "snapshot.json"), "--explain")
    said = [line for line in sentences(err) if "deny policy" in line]
    assert said == [
        "google_iam_deny_policy.guard_token_mint: creates a deny policy "
        "denying iam.serviceAccounts.getAccessToken, "
        "iam.serviceAccounts.getOpenIdToken to principalSet://goog/public:all, "
        "excepting principal://iam.googleapis.com/projects/-/serviceAccounts/"
        "payroll-ci@acme-pay-prod.iam.gserviceaccount.com"]


def test_a_removed_deny_policy_reads_as_the_guardrail_it_takes_away(capsys):
    """Scenario 6b, end to end: the removal arc names the denial it is
    REMOVING.

    The block's planned values are gone by design — that is what a deletion is —
    so the guardrail is read off the entry's own ``change.before``, through the
    same deny collections the proposal tier grades a new policy with. Announcing
    the denial as though it were being made, or reporting the block as
    unreadable, would both be wrong, and "deletes the deny policy" alone leaves
    the reader to go and look up what was in it.
    """
    plan = EXAMPLES / "terraform-denypolicy" / "plan_remove_deny.json"
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal", str(plan),
                              "--snapshot",
                              str(EXAMPLES / "terraform-denypolicy" /
                                  "snapshot.json"), "--explain")
    assert sentences(err) == [
        "google_iam_deny_policy.guard_token_mint: deletes the deny policy "
        "denying iam.serviceAccounts.getAccessToken, "
        "iam.serviceAccounts.getOpenIdToken to principalSet://goog/public:all"]


def test_a_conditional_deny_rule_says_it_is_conditional(capsys):
    """``has_condition`` on the rows becomes ", conditionally" — a denial that
    only sometimes applies must not read as one that always does."""
    policy = POLICIES / "deny_policy_conditional.json"
    _code, _out, err = invoke(capsys, "verify-policy", str(policy),
                              "--snapshot", str(SNAPSHOT), "--explain")
    assert sentences(err) == [
        "creates a deny policy denying iam.serviceAccounts.getAccessToken to "
        "principalSet://goog/public:all, conditionally"]


def test_an_org_policy_block_names_the_constraint_and_what_it_sets(capsys):
    """A terraform Org Policy block's rows carry the constraint and the enforce
    boolean, so the line says both — the flipped control the demo is about."""
    proposal = EXAMPLES / "terraform-orgpolicy" / \
        "proposal_serial_and_publicip.tf.json"
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(proposal), "--snapshot",
                              str(EXAMPLES / "terraform-orgpolicy" /
                                  "snapshot.json"), "--explain")
    assert ("google_org_policy_policy.serial_port_disabled: sets "
            "constraints/compute.disableSerialPortAccess enforce=false"
            ) in sentences(err)


def test_a_rest_org_policy_carries_its_node_polarity_and_reset(capsys, tmp_path):
    """A REST Org Policy is read from its own ``constraint_enforcement`` claims,
    which — unlike the terraform rows — keep the hierarchy node, the allowed and
    denied lists and the reset switch apart."""
    listed = tmp_path / "values.json"
    listed.write_text(json.dumps({
        "name": "organizations/123456789012/policies/compute.vmExternalIpAccess",
        "spec": {"rules": [{"values": {
            "allowedValues": ["projects/acme-prod/zones/z/instances/legacy"],
            "deniedValues": ["projects/acme-prod/zones/z/instances/retired"]}}]},
    }), encoding="utf-8")
    _code, _out, err = invoke(capsys, "verify-policy", str(listed), "--snapshot",
                              str(SNAPSHOT), "--explain")
    assert sentences(err) == [
        "spec.rules[0]: allows value projects/acme-prod/zones/z/instances/"
        "legacy for constraints/compute.vmExternalIpAccess at "
        "organizations/123456789012",
        "spec.rules[0]: denies value projects/acme-prod/zones/z/instances/"
        "retired for constraints/compute.vmExternalIpAccess at "
        "organizations/123456789012",
    ]

    reset = tmp_path / "reset.json"
    reset.write_text(json.dumps({
        "name": "folders/665544332211/policies/"
                "iam.disableServiceAccountKeyCreation",
        "spec": {"reset": True},
    }), encoding="utf-8")
    _code, _out, err = invoke(capsys, "verify-policy", str(reset), "--snapshot",
                              str(SNAPSHOT), "--explain")
    assert sentences(err) == [
        "spec: resets constraints/iam.disableServiceAccountKeyCreation at "
        "folders/665544332211 to the managed default"]


def test_a_custom_role_block_counts_the_permissions_it_defines(capsys):
    """The custom-role shape: the role's full name — the one value the rows
    carry that the claims do not — and how many permissions it grants."""
    proposal = EXAMPLES / "terraform-roles" / "proposal_a.tf.json"
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(proposal), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--explain")
    assert ("google_project_iam_custom_role.data_viewer_scoped: defines custom "
            "role projects/acme-prod/roles/dataViewerScoped with 4 permissions "
            "(bigquery.datasets.get, bigquery.jobs.create, bigquery.tables.get,"
            " bigquery.tables.getData)") in sentences(err)


def test_a_block_whose_rows_were_never_read_says_so(capsys):
    """A block of a shape this list speaks about that yielded no row says it
    could not be read — the collection abstained over it, and the abstention is
    a verdict above. Inventing a sentence for it is the failure mode."""
    plan = EXAMPLES / "terraform-denypolicy" / "plan_reset_payments.json"
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal", str(plan),
                              "--snapshot",
                              str(EXAMPLES / "terraform-denypolicy" /
                                  "snapshot.json"), "--explain")
    assert ("google_org_policy_policy.payments_default_sweep: could not be "
            "read — judged as a named abstention above") in sentences(err)


def test_a_collection_the_run_never_extracted_contributes_nothing(capsys):
    """The perimeter and the Cloud Armor policy of the demo proposal are listed
    in the proposal block above and have no row shape here: they contribute no
    sentence AND no apology line, because there is no collection whose rows they
    would have been."""
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(TF_PROPOSAL), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--explain")
    said = sentences(err)
    assert [line for line in said if "google_compute_security_policy" in line] == []
    assert [line for line in said
            if "google_access_context_manager" in line] == []
    assert "could not be read" not in "\n".join(said)


def test_the_sentences_are_ordered_by_block_and_bounded(capsys):
    """Deterministic order by block address, and the decision block's own
    elision shape past the cap — the rest is counted, never dropped in
    silence."""
    proposal = EXAMPLES / "terraform-orgpolicy" / \
        "proposal_serial_and_publicip.tf.json"
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(proposal), "--snapshot",
                              str(EXAMPLES / "terraform-orgpolicy" /
                                  "snapshot.json"), "--explain")
    said = sentences(err)
    assert len(said) == 9                       # eight blocks, then the count
    assert said[:-1] == sorted(said[:-1])
    assert said[-1] == "+5 more"


# -- the change story: what a delete or an update DOES --------------------------
#
# A create is its rows and nothing else. A delete and an update are not: the
# rows a delete plans are gone, and the rows an update plans say where the
# change lands, never what it moved. Both are told here from ``change.before``,
# read through the SAME collection extractors — the funnel
# ``iam_deny_checks.check_deny_wake_plan`` already reads the old side of a
# change with. So the assertions below are about the same join the create
# sentences are: the English names the rows a collection really read, and a
# before state nobody could read says exactly that instead of borrowing the new
# state's words.


NARROWED = AGENTIC / "network" / "B11_fw_narrowing.tfplan.json"
WIDENED = AGENTIC / "network" / "A01_fw_world_ssh_rdp.tfplan.json"
BLIND_UPDATE = AGENTIC / "benign" / "tfplan_firewall_narrow.json"
FULL_PLAN = POLICIES / "tf_plan_full.json"
DENY_SNAPSHOT = EXAMPLES / "terraform-denypolicy" / "snapshot.json"

#: The carve-out of scenario 6a, as the plan that THREADS it: one deny rule,
#: with and without the payroll-CI exception.
PAYROLL_CI = ("principal://iam.googleapis.com/projects/-/serviceAccounts/"
              "payroll-ci@acme-pay-prod.iam.gserviceaccount.com")
GUARD_RULE = {
    "denied_permissions": ["iam.googleapis.com/serviceAccounts.getAccessToken"],
    "denied_principals": ["principalSet://goog/public:all"],
}

#: The rule of scenario 1, so a deletion of it reads against a shape the README
#: quotes as a creation elsewhere.
WORLD_SSH = {
    "name": "allow-ssh-world",
    "network": "projects/acme-prod/global/networks/prod-vpc",
    "direction": "INGRESS", "priority": 1000, "disabled": False,
    "source_ranges": ["0.0.0.0/0"],
    "allow": [{"protocol": "tcp", "ports": ["22"]}],
}


def deny_policy(rule: dict) -> dict:
    """One ``google_iam_deny_policy``'s planned values, around one deny rule."""
    return {"name": "guard-token-mint",
            "parent": "cloudresourcemanager.googleapis.com%2F"
                      "projects%2Facme-pay-prod",
            "rules": [{"deny_rule": [rule]}]}


def org_policy(enforce: bool) -> dict:
    """One ``google_org_policy_policy``'s planned values, at one polarity."""
    return {"name": "organizations/123456789012/policies/"
                    "iam.disableServiceAccountKeyCreation",
            "parent": "organizations/123456789012",
            "spec": [{"rules": [{"enforce": enforce}]}]}


def changed_plan(tmp_path: Path, name: str, address: str, rtype: str,
                 action: str, before, after) -> Path:
    """A one-resource plan stating ONE change action, in ``terraform show
    -json``'s own shape: ``planned_values`` carries the new state (a deletion
    plans none) and ``resource_changes`` states the action with both sides."""
    resource = {"address": address, "mode": "managed",
                "name": address.split(".")[-1],
                "provider_name": "registry.terraform.io/hashicorp/google",
                "type": rtype}
    planned = [dict(resource, values=after)] if after is not None else []
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps({
        "format_version": "1.2", "terraform_version": "1.9.5",
        "planned_values": {"root_module": {"resources": planned}},
        "resource_changes": [dict(resource, change={
            "actions": [action], "before": before, "after": after})],
    }), encoding="utf-8")
    return path


def test_a_deleted_binding_names_the_grant_it_takes_away(capsys):
    """A removed member reads as the grant that goes with it — the role and the
    principal, off the binding rows the before state yielded, and "removes"
    because a binding is taken out of a policy rather than deleted outright."""
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(FULL_PLAN), "--snapshot", str(SNAPSHOT),
                              "--explain")
    assert ("google_project_iam_member.deprecated_ci: removes the IAM binding "
            "granting roles/editor to "
            "serviceAccount:ci@acme-prod.iam.gserviceaccount.com"
            ) in sentences(err)


def test_a_deleted_firewall_rule_names_what_it_was_allowing(capsys, tmp_path):
    """The opening a deletion closes, in the words the rule's own rows carry —
    a firewall rule that is going away is exactly the change whose planned
    values cannot describe it."""
    plan = changed_plan(tmp_path, "fw_delete",
                        "google_compute_firewall.allow_ssh_world",
                        "google_compute_firewall", "delete", WORLD_SSH, None)
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal", str(plan),
                              "--snapshot", str(AGENTIC_SNAPSHOT), "--explain")
    assert sentences(err) == [
        "google_compute_firewall.allow_ssh_world: deletes the firewall rule "
        "allowing INGRESS tcp/22 from 0.0.0.0/0 on "
        "projects/acme-prod/global/networks/prod-vpc"]


def test_a_deleted_org_policy_names_the_control_it_removes(capsys, tmp_path):
    """The constraint and the polarity the block was setting, from its own
    ``org_policy_rules`` row."""
    plan = changed_plan(tmp_path, "org_delete",
                        "google_org_policy_policy.sa_key_guard",
                        "google_org_policy_policy", "delete", org_policy(True),
                        None)
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal", str(plan),
                              "--snapshot", str(DENY_SNAPSHOT), "--explain")
    assert sentences(err) == [
        "google_org_policy_policy.sa_key_guard: deletes the Org Policy setting "
        "constraints/iam.disableServiceAccountKeyCreation enforce=true"]


def test_a_deletion_whose_before_state_is_unreadable_says_so(capsys, tmp_path):
    """A delete stating no before state at all: the block is named, the deletion
    is stated, and nothing is claimed about what was in it. Borrowing another
    block's content — or reading the deletion as a creation — is the failure
    mode this line exists to prevent."""
    plan = changed_plan(tmp_path, "deny_delete_blind",
                        "google_iam_deny_policy.guard_token_mint",
                        "google_iam_deny_policy", "delete", None, None)
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal", str(plan),
                              "--snapshot", str(DENY_SNAPSHOT), "--explain")
    assert sentences(err) == [
        "google_iam_deny_policy.guard_token_mint: deletes the deny policy "
        "whose prior content could not be read"]


def test_the_carve_out_of_6a_told_as_an_update_is_the_delta(capsys, tmp_path):
    """Scenario 6a's story, spelled by a plan that STATES the update: the
    threading reads as the principal it adds to the guardrail's exceptions, and
    names the rule it was threaded through.

    The plan the arc itself ships carries planned values only — it states no
    change action, so 6a reads as the creation it is (the test above pins that
    sentence end to end). Where a plan does state the update, the summary owes
    the reader the difference rather than the new state restated.
    """
    plan = changed_plan(tmp_path, "deny_thread",
                        "google_iam_deny_policy.guard_token_mint",
                        "google_iam_deny_policy", "update",
                        deny_policy(GUARD_RULE),
                        deny_policy({**GUARD_RULE,
                                     "exception_principals": [PAYROLL_CI]}))
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal", str(plan),
                              "--snapshot", str(DENY_SNAPSHOT), "--explain")
    assert sentences(err) == [
        f"google_iam_deny_policy.guard_token_mint: adds {PAYROLL_CI} to the "
        f"exceptionPrincipals of the deny rule denying "
        f"iam.serviceAccounts.getAccessToken"]


def test_an_updated_org_policy_reads_as_the_flag_it_flips(capsys, tmp_path):
    """A scalar field's delta: the new value with the old one beside it. The
    flipped control is the whole of what the change does, and a line saying only
    that the block "sets enforce=false" would read the same whether or not it
    was already false."""
    plan = changed_plan(tmp_path, "org_update",
                        "google_org_policy_policy.sa_key_guard",
                        "google_org_policy_policy", "update", org_policy(True),
                        org_policy(False))
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal", str(plan),
                              "--snapshot", str(DENY_SNAPSHOT), "--explain")
    assert sentences(err) == [
        "google_org_policy_policy.sa_key_guard: sets enforce=false (was true)"]


def test_a_moved_source_range_is_a_narrowing_or_a_widening(capsys):
    """The set-valued delta, and the one claim about coverage this block makes:
    "narrows" and "widens" are COMPUTED over the ranges the rows carry, so the
    same two fixtures read opposite ways round."""
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(NARROWED), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--explain")
    assert sentences(err) == [
        "google_compute_firewall.prod_web_admin: narrows source ranges from "
        "0.0.0.0/0 to 10.0.0.0/8"]

    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(WIDENED), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--explain")
    assert sentences(err) == [
        "google_compute_firewall.prod_web_admin: widens source ranges from "
        "10.0.0.0/8 to 0.0.0.0/0"]


def test_an_update_whose_before_state_could_not_be_read_states_the_new_one(
        capsys):
    """This plan's ``change.before`` is a mapping the firewall collection
    abstains over (it carries no allow or deny entry), so there is no old set of
    rows to difference. The line says that, and then says what the rule now
    allows — the new state stated as new, never as a delta nobody computed."""
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(BLIND_UPDATE), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--explain")
    assert sentences(err) == [
        "google_compute_firewall.ingest_https: updates the firewall rule whose "
        "prior content could not be read — now allowing INGRESS tcp/443 from "
        "10.0.0.0/8 on acme-prod-vpc"]


def test_an_update_whose_new_state_could_not_be_read_states_the_old_one(
        capsys, tmp_path):
    """The same refusal the other way round. Here the rule's NEW values carry
    no allow or deny entry, so the collection abstains over them: the block was
    not emptied, it was not read, and differencing against an abstention would
    report the first. The old state is stated as the old state instead."""
    plan = changed_plan(tmp_path, "fw_blind_after",
                        "google_compute_firewall.allow_ssh_world",
                        "google_compute_firewall", "update", WORLD_SSH,
                        {key: value for key, value in WORLD_SSH.items()
                         if key != "allow"})
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal", str(plan),
                              "--snapshot", str(AGENTIC_SNAPSHOT), "--explain")
    assert sentences(err) == [
        "google_compute_firewall.allow_ssh_world: updates the firewall rule "
        "whose new content could not be read — it was allowing INGRESS tcp/22 "
        "from 0.0.0.0/0 on projects/acme-prod/global/networks/prod-vpc"]


# -- the result row ------------------------------------------------------------


def _unchecked(err: str) -> int:
    """The recap's own ``unchecked=N``. The result row is asserted against THIS
    rather than a literal, so the two renderings of one count are pinned to each
    other and a fixture that gains an abstention cannot make them disagree."""
    recap = [line for line in err.splitlines() if line.startswith(RECAP)]
    assert len(recap) == 1
    return int(recap[0].split("unchecked=")[1].split()[0])


def test_an_approval_keeps_its_unchecked_qualifier(capsys):
    """An approval resting on abstentions keeps saying how many."""
    _code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                              str(SCHEMA_OK), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--provider-schema",
                              str(PROVIDER_SCHEMA), "--explain")
    unchecked = _unchecked(err)
    assert unchecked > 0
    assert row(err, "result") == f"APPROVED — {unchecked} unchecked (exit 0)"


def test_a_fully_decided_approval_carries_no_qualifier(capsys):
    """The bare word when nothing was left undecided: a run that checked
    everything must not read like one that checked nothing."""
    _code, _out, err = invoke(capsys, "verify-policy", str(GOOD),
                              "--snapshot", str(SNAPSHOT), "--explain")
    assert _unchecked(err) == 0
    assert row(err, "result") == "APPROVED (exit 0)"
    assert _result_lines(GroundingReport()) == \
        ["  result                  : APPROVED (exit 0)"]


def test_a_denial_names_only_the_built_in_findings_that_fired(capsys):
    """No requirements configured, so the denial is a built-in finding alone —
    and the promise clause must not appear at all."""
    code, _out, err = invoke(capsys, "verify-policy", "--proposal",
                             str(SCHEMA_PROPOSAL), "--snapshot",
                             str(AGENTIC_SNAPSHOT), "--provider-schema",
                             str(PROVIDER_SCHEMA), "--explain")
    assert code == 1
    assert row(err, "result") == "DENIED (exit 1)"
    assert "blocked by 1 built-in finding: [tf_attribute]" in section(err)
    assert "it violated these promises" not in section(err)


@_needs_z3
def test_a_denial_keeps_promises_and_built_in_findings_apart(capsys, tmp_path):
    """Both reasons on one denial, each naming its own vocabulary: promise IDS
    under the promises clause, verdict KINDS under the built-in one. Reporting
    either as the other is the mistake this row exists to make impossible."""
    compiled = compiled_requirements(tmp_path)
    capsys.readouterr()
    code, _out, err = invoke(capsys, "verify-policy", str(A10_POLICY),
                             "--snapshot", str(AGENTIC_SNAPSHOT),
                             "--requirements", str(compiled), "--explain")
    assert code == 1
    block = section(err)
    assert row(err, "result") == "DENIED (exit 1)"
    assert ("    it violated these promises:\n"
            "      no-primitive-roles-outside-domain\n") in block
    assert "blocked by 1 built-in finding: [principal]" in block
    # Neither vocabulary leaks into the other's clause. The violated clause is
    # a block now — id lines at six spaces, the author's sentence at eight —
    # so the id lines are what the built-in kind must stay out of. (The kind's
    # word can legitimately appear INSIDE a sentence its author wrote; it is
    # the reported ids that must be promise ids and nothing else.)
    violated = block[block.index("it violated these promises:"):]
    violated = violated[:violated.index("    blocked by ")]
    ids = [line.strip() for line in violated.splitlines()
           if line.startswith("      ") and not line.startswith("       ")]
    assert ids == ["no-primitive-roles-outside-domain"]
    assert "principal" not in " ".join(ids)
    blocked = block[block.index("blocked by "):]
    blocked = blocked[:blocked.index("\n")]
    assert "no-primitive-roles-outside-domain" not in blocked


def test_the_result_row_never_reads_a_promise_id_off_a_built_in_verdict():
    """The split is by verdict KIND, so a built-in finding whose target happens
    to look like a promise id still counts as a built-in finding."""
    report = GroundingReport()
    report.add(Verdict("contradicted", "firewall_exposure",
                       "no-open-ssh-rdp-ingress", 0, "a public source reaches it"))
    report.add(Verdict("ungrounded", "sec:iam", "no-public-principals", 0,
                       "refuted by iam_bindings[0]"))
    lines = _result_lines(report)
    assert lines == ["  result                  : DENIED (exit 1)",
                     "    it violated these promises:",
                     "      no-public-principals",
                     "    blocked by 1 built-in finding: [firewall_exposure]"]


def test_the_violated_promises_are_one_per_line_with_their_sentences():
    """One violated promise per line, the author's stored sentence under each,
    and the built-in clause still LAST so the reasons stay in one order.

    The sentences come from the rules the run admitted; a violated promise the
    caller handed no rule for keeps its id and gets no sentence."""
    report = GroundingReport()
    for promise_id in ("no-public-principals", "no-open-ssh-rdp-ingress",
                       "unregistered-promise"):
        report.add(Verdict("ungrounded", "sec:iam", promise_id, 0, "refuted"))
    lines = _result_lines(report, [_rule("no-public-principals", "No allUsers."),
                                   _rule("no-open-ssh-rdp-ingress", "No 0.0.0.0/0.")])
    assert lines == ["  result                  : DENIED (exit 1)",
                     "    it violated these promises:",
                     "      no-public-principals",
                     "        “No allUsers.”",
                     "      no-open-ssh-rdp-ingress",
                     "        “No 0.0.0.0/0.”",
                     "      unregistered-promise"]


def test_the_violated_promises_are_bounded_like_every_other_block():
    """Past the cap the rest is counted, never dropped in silence."""
    report = GroundingReport()
    for index in range(_SUMMARY_BLOCK_CAP + 2):
        report.add(Verdict("ungrounded", "sec:iam", f"promise-{index}", 0, "no"))
    lines = _result_lines(report)
    assert lines[2:] == [f"      promise-{index}"
                         for index in range(_SUMMARY_BLOCK_CAP)] + ["      +2 more"]


# -- the promises row, and the author's own English under each id --------------
#
# The block under the row is ONE LINE PER PROMISE, and the line under an id is
# the sentence the compiled artifact stored — the author's own words, the same
# text show_promises.py renders. So the assertions here are about that join in
# both directions: a sentence is the artifact's, read back off the rule objects
# the run admitted, and an id whose artifact carried no sentence stands alone
# rather than borrowing one.


def promise_block(err: str) -> list[str]:
    """The lines under the ``promises in force`` row, indent kept."""
    lines = section(err).splitlines()
    start = next(i for i, line in enumerate(lines)
                 if line.strip().startswith("promises in force"))
    out = []
    for line in lines[start + 1:]:
        if line.strip().startswith("provider"):
            break
        out.append(line)
    return out


def stored_sentences(compiled: Path) -> dict[str, str]:
    """Every promise's stored sentence, read from the artifacts the way
    ``show_promises.py`` reads them — the text the summary must not paraphrase.
    """
    return {promise["id"]: promise["source"]["text"]
            for path in sorted(compiled.glob("*.promises.json"))
            for promise in json.loads(path.read_text(encoding="utf-8"))["promises"]}


def _rule(promise_id: str, text: str | None = "") -> SimpleNamespace:
    """A stand-in for one admitted rule. ``text=None`` is the artifact that
    carried no sentence — a shape :class:`sec_artifact.Promise` refuses to
    hold, which is why the fallback is pinned through the renderer."""
    source = SimpleNamespace() if text is None else SimpleNamespace(text=text)
    return SimpleNamespace(promise=SimpleNamespace(id=promise_id, source=source))


@_needs_z3
def test_the_promises_row_agrees_with_the_promises_block(capsys, tmp_path):
    """One count of what enforces, shared with the block above it: the summary
    reads the same rules and the same carry verdicts, so it cannot call a
    promise enforcing that the block called stalled. The ids are no longer on
    the row — they are the block below it, one per line."""
    compiled = compiled_requirements(tmp_path)
    capsys.readouterr()
    _code, _out, err = invoke(capsys, "verify-policy", str(A10_POLICY),
                              "--snapshot", str(AGENTIC_SNAPSHOT),
                              "--requirements", str(compiled), "--explain")
    assert "promises in force (6 enforcing, 2 not" in err
    assert row(err, "promises in force") == \
        f"6 enforcing, 2 not — from {compiled} [cli]"


@_needs_z3
def test_each_promise_in_force_gets_a_line_and_the_authors_own_sentence(
        capsys, tmp_path):
    """One line per enforcing promise, ids sorted, and under each the sentence
    the artifact stored — verbatim, compared against the artifact itself."""
    compiled = compiled_requirements(tmp_path)
    capsys.readouterr()
    _code, _out, err = invoke(capsys, "verify-policy", str(A10_POLICY),
                              "--snapshot", str(AGENTIC_SNAPSHOT),
                              "--requirements", str(compiled), "--explain")
    stored = stored_sentences(compiled)
    enforcing = ["impersonation-sre-only", "no-open-ssh-rdp-ingress",
                 "no-primitive-roles-outside-domain", "no-public-principals",
                 "perimeter-restricts-storage", "sa-key-creation-disabled"]
    expected = []
    for promise_id in enforcing:
        expected.append(f"      {promise_id}")
        expected.append(f"        “{stored[promise_id]}”")
    assert promise_block(err)[:len(expected)] == expected


@_needs_z3
def test_a_promise_that_is_not_enforcing_states_its_stored_reason(
        capsys, tmp_path):
    """The two that never became rules are listed too, each with the reason the
    compile stored for it — the rejection reason, not a sentence of ours."""
    compiled = compiled_requirements(tmp_path)
    capsys.readouterr()
    _code, _out, err = invoke(capsys, "verify-policy", str(A10_POLICY),
                              "--snapshot", str(AGENTIC_SNAPSHOT),
                              "--requirements", str(compiled), "--explain")
    assert promise_block(err)[-4:] == [
        "      not enforcing  bigquery-reader-only",
        "        requirement was rejected at compile time (vocabulary is not "
        "grounded: roles/bigquery.reader does not exist in the snapshot); it "
        "did not run",
        "      not enforcing  untranslated-security-review-before-merge",
        "        no promise block — the sentence was not translated",
    ]


def test_a_promise_whose_artifact_stored_no_sentence_prints_its_id_alone():
    """No sentence in the artifact, no sentence in the block: an id on its own
    line is the answer, because the only other one is words nobody wrote."""
    assert _promise_block_lines([_rule("silent-promise", None),
                                 _rule("empty-promise", "")], ()) == [
        "      empty-promise", "      silent-promise"]


def test_a_long_sentence_is_truncated_at_the_cap_with_an_ellipsis():
    """The rule is TRUNCATE, not wrap: one line per promise is the block's
    whole shape, and a wrapped continuation reads as the next promise."""
    assert _PROMISE_TEXT_CAP == 160
    long = "No binding may grant " + "a" * 300
    lines = _promise_block_lines([_rule("long-promise", long)], ())
    assert lines[0] == "      long-promise"
    assert lines[1] == f"        “{long[:160]}…”"
    assert len(lines) == 2
    # Whitespace is collapsed, so a sentence wrapped in its markdown source
    # still prints as one line.
    assert _promise_block_lines([_rule("wrapped", "No\n  owner\tgrants.")],
                                ())[1] == "        “No owner grants.”"


def test_the_promise_block_is_bounded_and_counts_what_it_elided():
    """Both halves of the block cap at :data:`_SUMMARY_BLOCK_CAP`, and each
    counts its own remainder — an elision that silently dropped promises would
    read as a shorter corpus than the row above it counted."""
    rules = [_rule(f"promise-{index}") for index in range(_SUMMARY_BLOCK_CAP + 3)]
    stalled = [Verdict("unverified", "sec:iam", f"stalled-{index}", 0,
                       f"anchor.md:{index}: 'a sentence' — it did not compile")
               for index in range(_SUMMARY_BLOCK_CAP + 1)]
    lines = _promise_block_lines(rules, stalled)
    assert lines[_SUMMARY_BLOCK_CAP] == "      +3 more"
    assert lines[-1] == "      +1 more not enforcing"
    assert lines[-3:-1] == ["      not enforcing  stalled-7",
                            "        it did not compile"]


def test_one_stalled_promise_with_several_verdicts_is_listed_once():
    """The row counts distinct promise ids; the block must not print one id
    twice because two carry verdicts named it."""
    stalled = [Verdict("unverified", "sec:iam", "stalled", 0, "x — first"),
               Verdict("unverified", "sec:artifact", "stalled", 0, "x — second")]
    assert _promise_block_lines((), stalled) == [
        "      not enforcing  stalled", "        first"]


# -- hook mode and the non-explain paths ---------------------------------------


def test_hook_mode_never_prints_the_summary(capsys, monkeypatch):
    """``--hook --explain`` keeps the stderr it had: the agent-visible channel
    is not where a new block may appear."""
    event = json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Write",
                        "tool_input": {"file_path": str(GOOD), "content": ""}})
    monkeypatch.setattr("sys.stdin", io.StringIO(event))
    code, _out, err = invoke(capsys, "verify-policy", "--hook", "--snapshot",
                             str(SNAPSHOT), "--explain")
    assert code == 0
    assert "what was proposed:" in err     # the narrative itself is unchanged
    assert HEADER not in err
    assert RECAP not in err


def test_a_run_without_explain_carries_none_of_it(capsys):
    """Nothing new on either stream without the flag, and stdout is untouched
    by the flag — many tests pin those bytes."""
    plain_code, plain_out, plain_err = invoke(
        capsys, "verify-policy", str(GOOD), "--snapshot", str(SNAPSHOT))
    assert HEADER not in plain_err and RECAP not in plain_err
    for label in ("terraform state on disk", "proposed change", "result"):
        assert label not in plain_err
    explain_code, explain_out, _err = invoke(
        capsys, "verify-policy", str(GOOD), "--snapshot", str(SNAPSHOT),
        "--explain")
    assert (plain_code, plain_out) == (explain_code, explain_out)


def test_the_json_document_is_untouched_by_the_summary(capsys):
    """``--format json`` keeps stdout parseable: the block is stderr-only."""
    _code, out, err = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                             str(SNAPSHOT), "--format", "json", "--explain")
    assert HEADER in err
    assert HEADER not in out
    assert json.loads(out)["ok"] is True


# -- the renderer's own boundaries ---------------------------------------------


def test_the_section_survives_a_proposal_it_cannot_open(tmp_path):
    """A census that raises costs the census line and nothing else — the
    explain path never crashes a run the gate itself survived."""
    from gcp_grounding import discovery

    missing = str(tmp_path / "gone.tf.json")
    lines = _summary_section_lines(missing, GroundingReport(),
                                   discovery.Settings(), None, (), ())
    assert any(line.strip().startswith("proposed change") for line in lines)
    assert lines[-1].strip() == "result                  : APPROVED (exit 0)"


def test_the_label_column_is_one_column():
    """Every value starts in the same column, so the block reads down."""
    from gcp_grounding import discovery

    lines = _summary_section_lines(str(GOOD), GroundingReport(),
                                   discovery.Settings(), None, (), ())
    columns = {line.index(" : ") for line in lines if " : " in line}
    assert len(columns) == 1
