"""The provider-schema check family, pinned over hand-built proposals.

:mod:`gcp_grounding.tf_schema_checks` judges every ``google_*`` resource
block's attributes against the captured provider schema. Pinned here, in the
examples style:

* REGISTRATION — the module is a provider in ``PROVIDER_MODULES``, its check
  is a ``DOCUMENT_CHECK``, and its finding kinds are registered non-estate
  evidence so ``drift.adjudicate`` cannot rewrite an unknown-attribute
  ``ungrounded`` with a clause about what the current-state view proves;
* the FOUR BUCKETS — unknown attribute ``ungrounded`` with the edit-distance
  did-you-mean over the type's real names; attribute-vs-block, block-vs-
  attribute and scalar-vs-list shapes ``contradicted``; ``dynamic`` blocks and
  computed attributes ``unverified`` by name; a resource type absent from the
  schema ``ungrounded`` with its own did-you-mean;
* OFF-BY-ABSENCE and the one loud exception — nothing configured is
  byte-silent, a policy configured with no readable schema abstains naming
  the count of unjudged blocks;
* the POLICY TIERS — ``block`` keeps the honest statuses, ``annotate``
  demotes them to warnings carrying the same text, ``off`` is silent;
* MULTI-PROVIDER union — an attribute any supplied provider declares is not a
  finding, because the gate cannot always know which provider actuates;
* STALENESS — a schema past the ceiling demotes every finding to an
  abstention naming the age and the recapture command.
"""

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from gcp_grounding import drift, provider_schema, registry, tf_schema_checks
from gcp_grounding.core.report import Verdict
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.registry import CheckContext
from gcp_grounding import gate

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "examples" / "terraform-schema"
SCHEMA = EXAMPLE / "provider-schema.json"

KINDS = (tf_schema_checks.KIND_ATTRIBUTE, tf_schema_checks.KIND_BLOCK,
         tf_schema_checks.KIND_RESOURCE_TYPE, tf_schema_checks.KIND_NOTE)

STAMP = "2026-08-01T00:00:00+00:00"

#: A second, google-beta-only schema: the same firewall type, plus one
#: attribute the google schema does not declare.
BETA = {
    "provider_schemas": {
        "registry.terraform.io/hashicorp/google-beta": {
            "resource_schemas": {
                "google_compute_firewall": {"version": 1, "block": {
                    "attributes": {
                        "beta_only_knob": {"type": "string", "optional": True},
                    },
                }},
            },
        },
    },
}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """No exported configuration, no cached schema, no leaked runtime."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)
    provider_schema.reset_cache()
    yield
    provider_schema.reset_cache()


def install(**kw):
    kw.setdefault("paths", (str(SCHEMA),))
    provider_schema.activate(provider_schema.Runtime(**kw))


def document(name="proposal_ok.tf.json"):
    built = gate.terraform_proposal(str(EXAMPLE / name), raw=False)
    assert built.proposal is not None, built.note
    return built.proposal.document


def firewall_values(doc):
    resources = doc["planned_values"]["root_module"]["resources"]
    return next(r for r in resources
                if r["address"] == "google_compute_firewall.allow_health_checks"
                )["values"]


def check(doc, source="test.tf.json"):
    ctx = CheckContext(snapshot=GcpSnapshot(captured_at="t"),
                       solver=get_solver(), document=doc,
                       document_kind="tf_plan", source=source, claims=())
    return [v for v in tf_schema_checks.check_provider_schema(ctx)
            if v.kind in KINDS]


# -- registration ---------------------------------------------------------------


def test_the_check_is_registered_as_a_document_check():
    assert "gcp_grounding.tf_schema_checks" in registry.PROVIDER_MODULES
    assert tf_schema_checks.check_provider_schema in registry.document_checks()


def test_the_finding_kinds_are_registered_non_estate_evidence():
    """Without this, `drift.adjudicate` rule 4 rewrites the unknown-attribute
    `ungrounded` into an `unverified` claiming the CURRENT-STATE VIEW could not
    prove the absence — a fabricated reason, since these verdicts decide from
    the captured schema file and read no snapshot table."""
    for kind in (tf_schema_checks.KIND_ATTRIBUTE, tf_schema_checks.KIND_BLOCK,
                 tf_schema_checks.KIND_RESOURCE_TYPE):
        assert kind in drift.NON_ESTATE_KINDS, kind


def test_adjudicate_leaves_a_schema_finding_alone():
    from tests.test_gcp_drift import _ledger, _snapshot  # the frozen builders
    snapshot = _snapshot(_ledger())
    verdict = Verdict("ungrounded", tf_schema_checks.KIND_ATTRIBUTE,
                      "google_compute_firewall.src_ranges", 0, "not declared",
                      suggestions=("source_ranges",))
    assert drift.adjudicate((verdict,), [], snapshot, "annotate") == (verdict,)


# -- off-by-absence and the loud exception ---------------------------------------


def test_nothing_configured_is_byte_silent(tmp_path):
    assert check(document(), source=str(tmp_path / "main.tf.json")) == []


def test_a_policy_with_no_schema_abstains_naming_the_unjudged_count():
    install(paths=(), policy="block")
    verdicts = check(document())
    assert [v.status for v in verdicts] == ["unverified"]
    message = verdicts[0].message
    assert "NO provider schema is supplied" in message
    assert "3 google_* resource block(s) were NOT judged" in message
    assert provider_schema.CAPTURE_COMMAND in message


def test_an_unreadable_schema_is_loud_and_still_counts_the_unjudged(tmp_path):
    install(paths=(str(tmp_path / "absent.json"),))
    verdicts = check(document())
    assert [v.status for v in verdicts] == ["unverified", "unverified"]
    assert "could not be read" in verdicts[0].message
    assert "NOT judged against it" in verdicts[0].message
    assert "no configured provider schema could be read" in verdicts[1].message


def test_a_non_plan_document_kind_is_silence():
    install()
    ctx = CheckContext(snapshot=GcpSnapshot(captured_at="t"),
                       solver=get_solver(), document={"bindings": []},
                       document_kind="iam_policy", source="x", claims=())
    assert tf_schema_checks.check_provider_schema(ctx) == []


def test_a_document_with_no_google_resources_is_silence():
    install()
    assert check({"planned_values": {"root_module": {"resources": []}}}) == []


# -- the four buckets ------------------------------------------------------------


def test_an_unknown_attribute_is_ungrounded_with_the_did_you_mean():
    install()
    verdicts = check(document("proposal_typo.tf.json"))
    assert len(verdicts) == 1, verdicts
    finding = verdicts[0]
    assert finding.status == "ungrounded"
    assert finding.kind == tf_schema_checks.KIND_ATTRIBUTE
    assert "'src_ranges' is not an attribute or nested block" in finding.message
    assert "'terraform plan' under the provider" in finding.message
    assert finding.suggestions == ("source_ranges",)


def test_no_near_miss_means_the_recapture_guidance_instead():
    install()
    verdicts = check(document("proposal_newer.tf.json"))
    assert len(verdicts) == 1, verdicts
    finding = verdicts[0]
    assert finding.status == "ungrounded"
    assert finding.suggestions == ()
    assert "NEWER than the captured schema" in finding.message
    assert provider_schema.CAPTURE_COMMAND in finding.message


def test_an_attribute_written_as_a_block_is_contradicted():
    install()
    doc = document()
    firewall_values(doc)["source_ranges"] = [{"cidr": "10.0.0.0/8"}]
    verdicts = check(doc)
    assert [v.status for v in verdicts] == ["contradicted"]
    assert verdicts[0].kind == tf_schema_checks.KIND_BLOCK
    assert "written as a nested block" in verdicts[0].message
    assert "plain attribute" in verdicts[0].message


def test_a_block_written_as_an_attribute_is_contradicted():
    install()
    doc = document()
    firewall_values(doc)["allow"] = "tcp"
    verdicts = check(doc)
    assert [v.status for v in verdicts] == ["contradicted"]
    assert verdicts[0].kind == tf_schema_checks.KIND_BLOCK
    assert "declares 'allow' as a nested BLOCK" in verdicts[0].message


def test_a_scalar_where_a_list_is_declared_is_contradicted():
    install()
    doc = document()
    firewall_values(doc)["source_ranges"] = "0.0.0.0/0"
    verdicts = check(doc)
    assert [v.status for v in verdicts] == ["contradicted"]
    assert "SCALAR" in verdicts[0].message
    assert "set(string)" in verdicts[0].message


def test_nested_blocks_are_walked_with_the_same_rules():
    install()
    doc = document()
    firewall_values(doc)["allow"] = [{"protocol": "tcp", "portz": ["22"]}]
    verdicts = check(doc)
    assert len(verdicts) == 1, verdicts
    assert verdicts[0].status == "ungrounded"
    assert "allow[0]" in verdicts[0].message
    assert verdicts[0].suggestions == ("ports",)


def test_a_dynamic_block_abstains_by_name():
    install()
    doc = document()
    firewall_values(doc)["dynamic"] = [{"allow": {"for_each": "x"}}]
    verdicts = check(doc)
    assert [v.status for v in verdicts] == ["unverified"]
    assert "expanded at plan time" in verdicts[0].message


def test_a_computed_attribute_abstains_on_a_configuration_route():
    install()
    doc = document()
    firewall_values(doc)["self_link"] = "https://example/self"
    verdicts = check(doc)
    assert [v.status for v in verdicts] == ["unverified"]
    assert "COMPUTED attribute" in verdicts[0].message


def test_a_computed_attribute_on_a_real_plan_is_the_providers_own_output():
    install()
    doc = document()
    doc["terraform_version"] = "1.9.0"   # a real plan's marker
    firewall_values(doc)["self_link"] = "https://example/self"
    assert check(doc) == []


def test_an_unknown_resource_type_abstains_with_its_did_you_mean():
    """Adversarial-review repin: a type absent from the capture ABSTAINS, it
    is never blocked — a schema capture is complete per PROVIDER, the estate
    may actuate through providers nobody captured (google-beta beside
    google), and a type's provider membership cannot be read off its name.
    A partial capture proving a type absent was the measured false-positive
    (scenario 1's real GA types read as nonexistent against the demo
    capture). Attributes on a MATCHED type stay ungrounded — that
    enumeration is complete."""
    install()
    doc = document()
    resources = doc["planned_values"]["root_module"]["resources"]
    resources[0]["type"] = "google_compute_firewal"
    resources[0]["address"] = "google_compute_firewal.oops"
    verdicts = check(doc)
    typed = [v for v in verdicts
             if v.kind == tf_schema_checks.KIND_RESOURCE_TYPE]
    assert len(typed) == 1, verdicts
    assert typed[0].status == "unverified"
    assert "not defined by the captured provider schema" in typed[0].message
    assert "may belong to a provider that was not captured" in typed[0].message
    assert "google" in typed[0].message
    assert typed[0].suggestions == ("google_compute_firewall",)


def test_unreadable_planned_values_abstain_by_name():
    install()
    doc = document()
    resources = doc["planned_values"]["root_module"]["resources"]
    resources[0]["values"] = None
    verdicts = check(doc)
    notes = [v for v in verdicts if v.kind == tf_schema_checks.KIND_NOTE]
    assert len(notes) == 1
    assert "no readable planned values" in notes[0].message


def test_a_wrong_shaped_block_entry_abstains_instead_of_vanishing():
    install()
    doc = document()
    firewall_values(doc)["allow"] = ["tcp"]
    verdicts = check(doc)
    assert [v.status for v in verdicts] == ["unverified"]
    assert "not an object" in verdicts[0].message
    assert "NOT judged" in verdicts[0].message


def test_null_values_and_meta_arguments_are_never_findings():
    install()
    doc = document()
    values = firewall_values(doc)
    values["description"] = None
    values["count"] = 2
    values["lifecycle"] = [{"prevent_destroy": True}]
    assert check(doc) == []


# -- the policy tiers ------------------------------------------------------------


def test_annotate_demotes_findings_to_warnings_with_the_same_text():
    install(policy="annotate")
    verdicts = check(document("proposal_typo.tf.json"))
    assert [v.status for v in verdicts] == ["unverified"]
    assert "'src_ranges' is not an attribute" in verdicts[0].message
    assert "schema-policy 'annotate'" in verdicts[0].message
    assert verdicts[0].suggestions == ("source_ranges",)


def test_off_ignores_the_captured_schema():
    install(policy="off")
    assert check(document("proposal_typo.tf.json")) == []


def test_an_unrecognized_ambient_policy_abstains_rather_than_guessing(
        monkeypatch):
    monkeypatch.setenv(provider_schema.SCHEMA_POLICY_ENV, "blockk")
    monkeypatch.setenv(provider_schema.PROVIDER_SCHEMA_ENV, str(SCHEMA))
    verdicts = check(document("proposal_typo.tf.json"))
    assert [v.status for v in verdicts] == ["unverified"]
    assert "'blockk'" in verdicts[0].message
    assert "nothing was guessed" in verdicts[0].message


def test_the_ambient_environment_layer_reaches_the_check(monkeypatch):
    monkeypatch.setenv(provider_schema.PROVIDER_SCHEMA_ENV, str(SCHEMA))
    verdicts = check(document("proposal_typo.tf.json"))
    assert [v.status for v in verdicts] == ["ungrounded"]


# -- multi-provider union --------------------------------------------------------


def test_an_attribute_only_the_second_provider_declares_is_not_a_finding(
        tmp_path):
    beta = tmp_path / "google-beta.json"
    beta.write_text(json.dumps(BETA), encoding="utf-8")
    doc = document()
    firewall_values(doc)["beta_only_knob"] = "x"
    install()                                    # google alone: a finding
    assert [v.status for v in check(doc)] == ["ungrounded"]
    install(paths=(str(SCHEMA), str(beta)))      # union: no finding
    assert check(doc) == []


def test_a_resource_type_only_the_second_provider_defines_resolves(tmp_path):
    beta_only = deepcopy(BETA)
    table = beta_only["provider_schemas"][
        "registry.terraform.io/hashicorp/google-beta"]["resource_schemas"]
    table["google_beta_thing"] = table.pop("google_compute_firewall")
    beta = tmp_path / "google-beta.json"
    beta.write_text(json.dumps(beta_only), encoding="utf-8")
    doc = {"planned_values": {"root_module": {"resources": [{
        "address": "google_beta_thing.x", "mode": "managed",
        "type": "google_beta_thing", "name": "x",
        "values": {"beta_only_knob": "y"}}]}}}
    install(paths=(str(SCHEMA), str(beta)))
    assert check(doc) == []


# -- staleness -------------------------------------------------------------------


def _stale_schema(tmp_path):
    raw = json.loads(SCHEMA.read_text(encoding="utf-8"))
    path = tmp_path / "wrapped.json"
    path.write_text(json.dumps({
        "schema": provider_schema.WRAPPER_SCHEMA, "captured_at": STAMP,
        "raw": raw}), encoding="utf-8")
    return str(path)


def test_a_stale_schema_demotes_every_finding_and_says_why(tmp_path):
    install(paths=(_stale_schema(tmp_path),), now="2026-09-01T00:00:00+00:00")
    verdicts = check(document("proposal_typo.tf.json"))
    assert [v.status for v in verdicts] == ["unverified", "unverified"]
    note, finding = verdicts
    assert note.kind == tf_schema_checks.KIND_NOTE
    assert "31 days old" in note.message
    assert provider_schema.CAPTURE_COMMAND in note.message
    assert "'src_ranges' is not an attribute" in finding.message
    assert "[not decided:" in finding.message


def test_a_fresh_wrapped_schema_still_blocks(tmp_path):
    install(paths=(_stale_schema(tmp_path),), now="2026-08-02T00:00:00+00:00")
    verdicts = check(document("proposal_typo.tf.json"))
    assert [v.status for v in verdicts] == ["ungrounded"]


# -- through the registry funnel, over a plain snapshot ---------------------------


def test_the_registry_funnel_carries_the_finding_through():
    install()
    ctx = CheckContext(snapshot=GcpSnapshot(captured_at="t"),
                       solver=get_solver(),
                       document=document("proposal_typo.tf.json"),
                       document_kind="tf_plan", source="test", claims=())
    verdicts = [v for v in registry.run_document_checks(ctx)
                if v.kind in KINDS]
    assert [v.status for v in verdicts] == ["ungrounded"]
    assert verdicts[0].suggestions == ("source_ranges",)
