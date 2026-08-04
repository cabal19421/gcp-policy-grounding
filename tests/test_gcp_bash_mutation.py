"""Pure unit tests for the offline bash-mutation classifier.

No subprocess, no network. A parametrized table maps >40 concrete shell
commands to their expected (status, cli, verb), plus focused tests for risk
evidence, compound splitting, the honest verdict mapping, and robustness."""

import pytest

from gcp_grounding.bash_mutation import (
    KNOWN_CLIS,
    MUTATING_LEAF_VERBS,
    READ_ONLY_LEAF_VERBS,
    MutationFinding,
    bash_mutation_verdicts,
    scan_command,
)
from gcp_grounding.core.report import GroundingReport, Verdict

# (command, status, cli, verb); status None means NO finding at all.
CASES = [
    # -- mutating gcloud -----------------------------------------------------
    ("gcloud projects add-iam-policy-binding my-proj "
     "--member=user:evil@evil.com --role=roles/owner",
     "mutating", "gcloud", "gcloud projects add-iam-policy-binding"),
    ("gcloud projects remove-iam-policy-binding my-proj "
     "--member=user:evil@evil.com --role=roles/editor",
     "mutating", "gcloud", "gcloud projects remove-iam-policy-binding"),
    ("gcloud projects set-iam-policy my-proj policy.json",
     "mutating", "gcloud", "gcloud projects set-iam-policy"),
    ("gcloud resource-manager org-policies disable-enforce "
     "constraints/compute.requireOsLogin --project=my-proj",
     "mutating", "gcloud",
     "gcloud resource-manager org-policies disable-enforce"),
    ("gcloud org-policies set-policy policy.yaml",
     "mutating", "gcloud", "gcloud org-policies set-policy"),
    ("gcloud compute firewall-rules create allow-all --allow=tcp:22 "
     "--source-ranges=0.0.0.0/0",
     "mutating", "gcloud", "gcloud compute firewall-rules create"),
    ("gcloud compute firewall-policies rules create 1000 --action=allow "
     "--firewall-policy=fp",
     "mutating", "gcloud", "gcloud compute firewall-policies rules create"),
    ("gcloud compute security-policies rules create 1 --security-policy=sp "
     "--action=allow --src-ip-ranges=0.0.0.0/0",
     "mutating", "gcloud", "gcloud compute security-policies rules create"),
    ("gcloud access-context-manager perimeters update my-perimeter "
     "--add-resources=projects/123",
     "mutating", "gcloud", "gcloud access-context-manager perimeters update"),
    ("gcloud iam service-accounts keys create key.json "
     "--iam-account=sa@proj.iam.gserviceaccount.com",
     "mutating", "gcloud", "gcloud iam service-accounts keys create"),
    ("gcloud iam roles update customRole --project=my-proj "
     "--add-permissions=resourcemanager.projects.get",
     "mutating", "gcloud", "gcloud iam roles update"),
    ("gcloud compute instances delete my-vm --zone=us-central1-a",
     "mutating", "gcloud", "gcloud compute instances delete"),
    ("gcloud services enable compute.googleapis.com",
     "mutating", "gcloud", "gcloud services enable"),
    ("gcloud pubsub topics create my-topic",
     "mutating", "gcloud", "gcloud pubsub topics create"),
    # -- mutating terraform / terragrunt ------------------------------------
    ("terraform apply -auto-approve", "mutating", "terraform", "terraform apply"),
    ("terraform destroy -auto-approve",
     "mutating", "terraform", "terraform destroy"),
    ("terraform state rm aws_instance.foo",
     "mutating", "terraform", "terraform state rm"),
    ("terraform state mv aws_instance.a aws_instance.b",
     "mutating", "terraform", "terraform state mv"),
    ("terragrunt apply -auto-approve",
     "mutating", "terragrunt", "terragrunt apply"),
    # -- mutating gsutil / bq / kubectl -------------------------------------
    ("gsutil iam ch allUsers:objectViewer gs://my-bucket",
     "mutating", "gsutil", "gsutil iam ch"),
    ("gsutil rm gs://my-bucket/object", "mutating", "gsutil", "gsutil rm"),
    ("gsutil mb gs://new-bucket", "mutating", "gsutil", "gsutil mb"),
    ("bq update --description new my_dataset", "mutating", "bq", "bq update"),
    ("kubectl apply -f rbac.yaml", "mutating", "kubectl", "kubectl apply"),
    ("kubectl delete -f rbac.yaml", "mutating", "kubectl", "kubectl delete"),
    # -- mutating curl (googleapis.com + write method) ----------------------
    ("curl -X POST -d @body.json "
     "https://cloudresourcemanager.googleapis.com/v1/projects/my-proj:setIamPolicy",
     "mutating", "curl", "curl POST"),
    ("curl -X PUT -d @b.json https://storage.googleapis.com/upload/foo",
     "mutating", "curl", "curl PUT"),
    ("curl --request DELETE https://compute.googleapis.com/compute/v1/foo",
     "mutating", "curl", "curl DELETE"),
    ("curl -d name=foo https://iam.googleapis.com/v1/projects",
     "mutating", "curl", "curl POST"),
    # -- read-only: NO finding ----------------------------------------------
    ("gcloud projects get-iam-policy my-proj", None, None, None),
    ("gcloud iam roles list", None, None, None),
    ("gcloud compute firewall-rules describe allow-all", None, None, None),
    ("gcloud compute instances list", None, None, None),
    ("terraform plan", None, None, None),
    ("terraform show -json", None, None, None),
    ("terraform validate", None, None, None),
    ("gsutil ls gs://my-bucket", None, None, None),
    ("bq show my_dataset", None, None, None),
    ("kubectl get pods", None, None, None),
    ("curl https://iam.googleapis.com/v1/roles", None, None, None),
    ("curl -X GET https://iam.googleapis.com/v1/roles", None, None, None),
    # -- benign / not this gate's business: NO finding ----------------------
    ("pytest -q", None, None, None),
    ("git commit -m x", None, None, None),
    ("python -m gcp_grounding verify-policy p.json", None, None, None),
    ("echo gcloud projects add-iam-policy-binding", None, None, None),
    ("curl https://example.com/health", None, None, None),
    ("cd /tmp", None, None, None),
    # -- unrecognized: abstain ----------------------------------------------
    ("gcloud compute instances frobnicate x",
     "unrecognized", "gcloud", "gcloud compute instances frobnicate x"),
    ("gcloud beta wibble wobble",
     "unrecognized", "gcloud", "gcloud beta wibble wobble"),
    ('gcloud projects create "unclosed', "unrecognized", "", ""),
]


@pytest.mark.parametrize("command,status,cli,verb", CASES)
def test_scan_command_table(command, status, cli, verb):
    findings = scan_command(command)
    if status is None:
        assert findings == []
        return
    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == status
    assert finding.cli == cli
    assert finding.verb == verb


def test_table_covers_at_least_forty_commands():
    assert len(CASES) >= 40


# -- public surface ---------------------------------------------------------


def test_public_api_and_vocabularies():
    import gcp_grounding.bash_mutation as module
    assert set(module.__all__) == {
        "MutationFinding", "scan_command", "bash_mutation_verdicts",
        "MUTATING_LEAF_VERBS", "READ_ONLY_LEAF_VERBS", "KNOWN_CLIS"}
    assert "add-iam-policy-binding" in MUTATING_LEAF_VERBS
    assert "set-iam-policy" in MUTATING_LEAF_VERBS
    assert "list" in READ_ONLY_LEAF_VERBS
    assert "get-iam-policy" in READ_ONLY_LEAF_VERBS
    assert KNOWN_CLIS == frozenset({
        "gcloud", "gsutil", "bq", "terraform", "terragrunt", "kubectl",
        "curl", "wget"})
    # the two tables never overlap — a verb cannot be both.
    assert not (MUTATING_LEAF_VERBS & READ_ONLY_LEAF_VERBS)


def test_finding_is_frozen():
    finding = scan_command("terraform destroy -auto-approve")[0]
    assert isinstance(finding, MutationFinding)
    with pytest.raises(AttributeError):
        finding.status = "mutated"


# -- risk evidence ----------------------------------------------------------


def test_roles_owner_and_external_member_are_evidence():
    finding = scan_command(
        "gcloud projects add-iam-policy-binding my-proj "
        "--member=user:evil@evil.com --role=roles/owner")[0]
    assert finding.status == "mutating"
    assert "roles/owner" in finding.detail
    assert "user:evil@evil.com" in finding.detail
    assert "flags seen:" in finding.detail


def test_open_firewall_range_is_evidence():
    finding = scan_command(
        "gcloud compute firewall-rules create allow-all --allow=tcp:22 "
        "--source-ranges=0.0.0.0/0")[0]
    assert "0.0.0.0/0" in finding.detail


def test_internal_member_is_not_flagged():
    finding = scan_command(
        "gcloud projects add-iam-policy-binding my-proj "
        "--member=user:alice@acme.example --role=roles/viewer")[0]
    assert finding.status == "mutating"
    assert "flags seen:" not in finding.detail


def test_auto_approve_lands_in_detail():
    finding = scan_command("terraform apply -auto-approve")[0]
    assert "-auto-approve" in finding.detail


def test_evidence_never_changes_status():
    # allUsers is dangerous evidence but the verb is what decides mutating.
    finding = scan_command("gsutil iam ch allUsers:objectViewer gs://b")[0]
    assert finding.status == "mutating"
    assert "allUsers" in finding.detail


# -- unrecognized / tokenization -------------------------------------------


def test_unbalanced_quotes_abstain_without_raising():
    findings = scan_command('gcloud projects create "unclosed')
    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == "unrecognized"
    assert finding.cli == ""
    assert finding.verb == ""
    assert finding.detail == "the command could not be tokenized — not decided"


def test_unknown_verb_names_itself_verbatim():
    finding = scan_command("gcloud compute instances frobnicate x")[0]
    assert finding.status == "unrecognized"
    assert "frobnicate" in finding.detail


# -- compound & ordering ----------------------------------------------------


def test_compound_yields_two_mutating_findings_in_order():
    command = ("cd /tmp && gcloud projects add-iam-policy-binding my-proj "
               "--member=user:evil@evil.com --role=roles/owner ; "
               "terraform apply -auto-approve")
    findings = scan_command(command)
    assert [f.status for f in findings] == ["mutating", "mutating"]
    assert findings[0].verb == "gcloud projects add-iam-policy-binding"
    assert findings[1].verb == "terraform apply"


def test_newline_separator_preserves_order():
    findings = scan_command(
        "gcloud pubsub topics create t\nterraform apply -auto-approve")
    assert [f.verb for f in findings] == ["gcloud pubsub topics create",
                                          "terraform apply"]


def test_pipe_separator_splits_segments():
    findings = scan_command(
        "gcloud iam roles list | gcloud projects set-iam-policy p pol.json")
    assert [f.verb for f in findings] == ["gcloud projects set-iam-policy"]


def test_separators_inside_quotes_are_not_split():
    # the ';' and '&&' live inside a quoted --description and must not split.
    findings = scan_command(
        'gcloud pubsub topics create t --description "a; b && c"')
    assert len(findings) == 1
    assert findings[0].verb == "gcloud pubsub topics create"


# -- the four-bucket-honesty verdict mapping --------------------------------


def test_mutating_verdict_is_unverified_bash_mutation():
    verdicts = bash_mutation_verdicts("terraform apply -auto-approve")
    assert len(verdicts) == 1
    verdict = verdicts[0]
    assert isinstance(verdict, Verdict)
    assert verdict.status == "unverified"
    assert verdict.kind == "bash-mutation"
    assert verdict.target == "terraform apply"
    assert "mutates GCP state directly" in verdict.message


def test_unrecognized_verdict_uses_command_placeholder():
    verdicts = bash_mutation_verdicts('gcloud projects create "unclosed')
    assert len(verdicts) == 1
    verdict = verdicts[0]
    assert verdict.status == "unverified"
    assert verdict.kind == "bash-unrecognized"
    assert verdict.target == "<command>"
    assert verdict.message.endswith("not decided")


def test_mutations_leave_report_ok_true():
    command = ("gcloud projects add-iam-policy-binding my-proj "
               "--member=user:evil@evil.com --role=roles/owner ; "
               "terraform destroy -auto-approve")
    report = GroundingReport()
    for verdict in bash_mutation_verdicts(command):
        report.add(verdict)
    assert len(report.verdicts) == 2
    assert report.ok is True  # unverified never fails the gate


def test_source_kwarg_is_accepted():
    assert bash_mutation_verdicts("terraform apply -auto-approve",
                                  source="Bash") \
        == bash_mutation_verdicts("terraform apply -auto-approve")


# -- robustness: scan_command never raises ----------------------------------


@pytest.mark.parametrize("command", [
    "",
    "   ",
    "\n\n\n",
    "\t;|&&||",
    "gcloud\x00projects\x01create",
    "gcloud projects create \x7f\x1b[31m",
    "|| ; && | ;",
])
def test_scan_never_raises(command):
    result = scan_command(command)
    assert isinstance(result, list)


def test_non_string_input_returns_empty():
    assert scan_command(None) == []  # type: ignore[arg-type]


def test_large_command_is_handled_and_segment_truncated():
    command = ("gcloud projects add-iam-policy-binding "
               + "x" * 100_000
               + " --member=user:evil@evil.com --role=roles/owner")
    findings = scan_command(command)
    assert len(findings) == 1
    assert findings[0].status == "mutating"
    assert findings[0].verb == "gcloud projects add-iam-policy-binding"
    assert len(findings[0].segment) <= 200


def test_many_embedded_newlines_do_not_raise():
    command = "\n".join(["terraform apply -auto-approve"] * 500)
    findings = scan_command(command)
    assert len(findings) == 500
    assert all(f.status == "mutating" for f in findings)
