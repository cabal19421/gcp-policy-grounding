"""Acceptance for ``gcp_grounding.tfsource.plan``, THE terraform plan-JSON
reader.

Driven from the committed ``tests/fixtures/gcp/tf/estate_plan.json``, which was
authored to carry all four input shapes one plan can hold at once — a
``prior_state``, a ``resource_changes`` array with every action in the
vocabulary (including the two-element delete-then-create replacement and a
``deposed``-keyed delete sitting beside the create at the same address), a
``planned_values`` tree with a nested child module, a ``resource_drift`` entry,
an ``after_unknown`` mirror on the create, and the grep-able secret sentinels.

The load-bearing tests here are the ones that pin a SILENT failure:

- the CURRENT/PROPOSED split, asserted as its OWN test because both arms read
  the same file: a shared source spelling would make ``TfObject``'s
  biconditional vacuous and let a proposed change be read back as evidence of
  what currently exists, which grounds the change against itself;
- the no-prior-state arm, where the tempting fallback (``planned_values``) is
  the proposal, so the failure is a clean pass on every widening check;
- the DELETE RULE, where the failure is not a crash but a destroy plan that
  produces no facts and so looks exactly like an empty plan;
- ``after_unknown``, where the failure is an attribute nobody has seen reading
  as unset;
- and ``resource_drift``, asserted BY VALUE — the drifted resource is also in
  ``prior_state``, so "zero objects from drift" is only checkable by proving the
  surviving object carries the refreshed value and not the drift entry's.

``terraform`` is not installed on this machine and nothing here needs it.
"""

import copy
import importlib.util
import inspect
import json
from pathlib import Path

import pytest

from gcp_grounding import facts, provenance
from gcp_grounding.facts import TfObject
from gcp_grounding.tf_claims import terraform_plan_claims
from gcp_grounding.tfsource import plan

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
PLAN_PATH = FIXTURES / "tf" / "estate_plan.json"
PLAN = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
ESTATE = json.loads((FIXTURES / "estate_snapshot.json").read_text(encoding="utf-8"))

#: The frozen module this reader may not disturb. ``as_plan_document`` exists so
#: nobody writes a second extraction path; this file is the proof the first one
#: is untouched.
CLAIMS_TF_PATH = Path(__file__).parent / "test_gcp_claims_tf.py"

#: A deterministic stamp, so a test that is not about the capture time does not
#: depend on a checkout's mtimes.
STAMP = "2026-01-05T00:00:00Z"

#: The plaintext sentinels the fixture plants. ``FIXTURE-PLAN-SECRET`` is the
#: one this reader is responsible for: it sits in ``planned_values``, in a
#: ``change.after`` and in ``prior_state``, so all four arms have to remove it.
PLAN_SECRET = "FIXTURE-PLAN-SECRET"
SENTINELS = ("FIXTURE-SECRET-DO-NOT-LEAK", "FIXTURE-SECRET-BY-NAME", PLAN_SECRET)

CHILD_ADDRESS = "module.net.google_compute_firewall.allow-health-checks"
DRIFTED = 'module.net.google_compute_firewall.allow-iap-ssh["prod"]'
DELETED = "google_compute_firewall.deny-ssh-external[0]"
DELETED_KEY = "projects/acme-prod/global/firewalls/deny-ssh-external"
CREATED = "google_compute_firewall.allow-db-internal"
BEFORE_ONLY = "google_project_iam_member.legacy-viewer"
BOTH_SIDES = "google_compute_firewall.allow-internal"

#: The three positions the fixture's ``after_unknown`` marks with exactly
#: ``true`` on the created firewall: one inside a nested block, and two
#: top-level computed attributes that are absent from ``after`` altogether.
CREATED_UNKNOWN = ("allow[0].ports", "id", "self_link")


@pytest.fixture(scope="module")
def read():
    """The committed fixture, read once with a pinned capture time."""
    return plan.read_plan(PLAN_PATH, captured_at=STAMP)


def _prior_addresses():
    """Every address ``prior_state`` covers, straight out of the fixture."""
    found = []

    def walk(module):
        for resource in module.get("resources") or ():
            found.append(resource["address"])
        for child in module.get("child_modules") or ():
            walk(child)

    walk(PLAN["prior_state"]["values"]["root_module"])
    return set(found)


def _rendered(objects):
    """Every attribute value of every object as text, for a leak assertion.
    ``default=repr`` is what renders a ``Redacted``, whose repr is a digest, and
    an ``Unresolved``, whose repr carries no detail."""
    return json.dumps([obj.values for obj in objects], default=repr, sort_keys=True)


def _without(*keys):
    return {key: value for key, value in PLAN.items() if key not in keys}


# -- ARM 1: prior_state as CURRENT ----------------------------------------


def test_prior_state_facts_land_at_tfplan_prior_and_include_the_child_module(read):
    assert read.ok is True
    assert plan.ARM_PRIOR_STATE in read.arms
    current = read.current_by_address()
    # Every address prior_state covers survives onto the current side.
    assert _prior_addresses() <= set(current)
    # The nested child module is the one a walker that forgets `child_modules`
    # drops, and it drops it silently.
    child = current[CHILD_ADDRESS]
    assert child.source == plan.PRIOR_SOURCE == "tfplan-prior"
    assert child.side == "current"
    assert child.module == "module.net"
    assert child.values["source_ranges"] == ["35.191.0.0/16", "130.211.0.0/22"]
    assert child.values["target_tags"] == ["web"]
    # An indexed address in that same module keeps its index key.
    drifted = current[DRIFTED]
    assert drifted.index_key == "prod"
    assert drifted.module == "module.net"


def test_prior_state_carries_the_never_complete_note(read):
    assert plan.NEVER_COMPLETE_NOTE.format(path=str(PLAN_PATH)) in read.notes


# -- ARM 2: change.before as CURRENT --------------------------------------


def test_a_before_address_absent_from_prior_state_produces_a_current_fact(read):
    assert BEFORE_ONLY not in _prior_addresses()
    obj = read.current_by_address()[BEFORE_ONLY]
    assert (obj.source, obj.side) == (plan.PRIOR_SOURCE, "current")
    assert obj.values["role"] == "roles/viewer"
    assert obj.values["member"] == "group:data-eng@acme.example"


def test_a_pure_create_contributes_no_current_fact(read):
    # `change.before` is null for a create, which is not a gap in the plan: a
    # created resource legitimately has no predecessor.
    assert CREATED not in read.current_by_address()
    assert read.action_of(CREATED) == "create"


def test_an_address_in_both_resolves_to_the_before_side_value():
    # A change's `before` is the exact predecessor of the exact resource under
    # review, so it outranks the same address read from the whole-workspace
    # refresh. The fixture agrees on both sides, so the two are forced apart
    # here — otherwise the precedence is untested by construction.
    document = copy.deepcopy(PLAN)
    for resource in document["prior_state"]["values"]["root_module"]["resources"]:
        if resource["address"] == BOTH_SIDES:
            resource["values"]["priority"] = 1234
            break
    else:                                     # pragma: no cover - fixture drift
        pytest.fail(f"{BOTH_SIDES} is no longer in the fixture's prior state")

    result = plan.read_plan_document(document, origin="<both>")
    assert result.current_by_address()[BOTH_SIDES].values["priority"] == 1000
    assert sum(obj.address == BOTH_SIDES for obj in result.current) == 1


def test_the_before_side_override_is_named_in_a_note(read):
    override = [note for note in read.notes
                if "appear in BOTH 'prior_state' and a 'change.before'" in note]
    assert len(override) == 1
    for address in (BOTH_SIDES, DELETED, "google_compute_security_policy.edge-waf",
                    "google_org_policy_policy.vm-external-ip"):
        assert address in override[0]
    # ...and an address only `change.before` covers is not an override, so it is
    # deliberately absent from that list.
    assert BEFORE_ONLY not in override[0]


def test_a_deposed_delete_contributes_no_current_fact(read):
    # The deposed generation is the OLD object a create-before-destroy left
    # behind; letting its `before` win would resurrect it as current state.
    account = read.current_by_address()["google_service_account.etl-runner"]
    assert account.values["account_id"] == "etl-runner"
    assert any("DEPOSED change entr" in note for note in read.notes)


# -- the no-prior-state arm ------------------------------------------------


def test_a_plan_with_no_prior_state_emits_the_note_and_no_current_from_planned():
    result = plan.read_plan_document(_without("prior_state"), origin="<no-prior>")
    assert result.ok is True
    assert plan.NO_PRIOR_STATE_NOTE.format(path="<no-prior>") in result.notes
    # Only `change.before` may contribute. Every address `planned_values` alone
    # covers must be absent from the current side.
    changed = {entry["address"] for entry in PLAN["resource_changes"]}
    assert set(result.current_by_address()) <= changed
    assert CHILD_ADDRESS not in result.current_by_address()


def test_planned_values_alone_produce_zero_current_facts():
    result = plan.read_plan_document(_without("prior_state", "resource_changes"),
                                     origin="<planned-only>")
    assert result.ok is True
    assert result.current == ()
    assert plan.NO_PRIOR_STATE_NOTE.format(path="<planned-only>") in result.notes
    # ...and the very same resources still populate the PROPOSED side, so the
    # emptiness above is a decision and not a parse failure.
    assert CHILD_ADDRESS in result.proposed_by_address()


# -- the action vocabulary -------------------------------------------------


def test_every_action_in_the_fixture_maps():
    seen = set()
    for entry in PLAN["resource_changes"]:
        action, note = plan.normalize_action(entry["change"]["actions"])
        assert note == "", entry["address"]
        assert action in plan.ACTIONS
        seen.add(action)
    assert seen == {"no-op", "create", "update", "delete", "replace"}


def test_the_two_element_delete_then_create_maps_to_replace(read):
    entry, = [e for e in PLAN["resource_changes"]
              if e["change"]["actions"] == ["delete", "create"]]
    assert entry["address"] == "google_org_policy_policy.vm-external-ip"
    assert plan.normalize_action(["delete", "create"]) == ("replace", "")
    assert plan.normalize_action(["create", "delete"]) == ("replace", "")
    assert read.action_of("google_org_policy_policy.vm-external-ip") == "replace"


def test_an_unrecognised_action_becomes_update_with_a_note():
    action, note = plan.normalize_action(["forget"])
    assert action == plan.FALLBACK_ACTION == "update"
    assert "forget" in note and "update" in note
    assert plan.normalize_action("delete")[0] == plan.FALLBACK_ACTION


# -- THE DELETE RULE -------------------------------------------------------


def _firewall_record(values):
    """The estate-shaped ``firewall_rules`` record for a
    ``google_compute_firewall``'s attributes.

    The real mapper is a separate task and this is NOT it — it is the smallest
    projection that lets this test state its requirement exactly: the object a
    deletion produces has to carry EVERY attribute that record is built from,
    because a delete's `after` is null and the whole rule exists to stop that
    from becoming an absence of facts.
    """
    action = "deny" if "deny" in values else "allow"
    return {
        "action": action,
        "destination_ranges": values["destination_ranges"],
        "direction": values["direction"],
        "disabled": values["disabled"],
        "layer4": values[action],
        "network": values["network"],
        "priority": values["priority"],
        "source_ranges": values["source_ranges"],
        "source_service_accounts": values["source_service_accounts"],
        "source_tags": values["source_tags"],
        "target_service_accounts": values["target_service_accounts"],
        "target_tags": values["target_tags"],
    }


def test_the_deleted_rule_maps_to_a_record_equal_to_the_estate_fixtures(read):
    proposed = read.proposed_by_address()[DELETED]
    assert read.action_of(DELETED) == "delete"
    assert (proposed.source, proposed.side) == (plan.PROPOSED_SOURCE, "proposed")
    # `change.after` is null here; without the delete rule there would be no
    # object at all and a destroy plan would read as an empty plan.
    assert proposed.values["id"] == DELETED_KEY
    assert _firewall_record(proposed.values) == ESTATE["firewall_rules"][DELETED_KEY]
    assert any("what the plan REMOVES" in note for note in proposed.notes)


def test_a_null_after_that_is_not_a_delete_builds_no_proposed_object():
    document = copy.deepcopy(PLAN)
    for entry in document["resource_changes"]:
        if entry["address"] == DELETED:
            entry["change"]["actions"] = ["update"]
            break
    result = plan.read_plan_document(document, origin="<not-a-delete>")
    assert DELETED not in result.proposed_by_address()
    assert result.action_of(DELETED) == "update"
    assert any("null 'change.after'" in note for note in result.notes)


# -- AFTER-UNKNOWN ---------------------------------------------------------


def test_the_after_unknown_create_path_produces_markers_at_three_paths(read):
    created = read.proposed_by_address()[CREATED]
    found = dict(facts.unresolved_in(created.values))
    assert tuple(sorted(found)) == CREATED_UNKNOWN
    for path, marker in found.items():
        assert marker.reason == "unknown_after_apply"
        assert marker.path == path
    # The nested one was created inside a block that already existed, and the
    # two top-level ones are absent from `after` entirely — which is exactly
    # what makes a missing key ambiguous without this walk.
    assert created.values["allow"][0]["protocol"] == "tcp"
    assert facts.is_unresolved(created.values["allow"][0]["ports"])
    assert "id" not in PLAN["resource_changes"][1]["change"]["after"]
    assert "self_link" not in PLAN["resource_changes"][1]["change"]["after"]
    assert created.unresolved == tuple(found[key] for key in sorted(found))


def test_after_unknown_paths_returns_those_same_paths():
    entry, = [e for e in PLAN["resource_changes"] if e["address"] == CREATED]
    assert plan.after_unknown_paths(entry) == CREATED_UNKNOWN
    # The exported helper takes the entry OR the change itself.
    assert plan.after_unknown_paths(entry["change"]) == CREATED_UNKNOWN
    marked = plan.unknown_marked(entry)
    assert tuple(sorted(path for path, _ in facts.unresolved_in(marked))) \
        == CREATED_UNKNOWN
    # A `false` and an empty container mark nothing, so neither mints a key.
    assert marked["destination_ranges"] == []
    assert marked["source_ranges"] == ["10.0.0.0/8"]


def test_a_marker_refuses_truthiness(read):
    created = read.proposed_by_address()[CREATED]
    with pytest.raises(TypeError):
        bool(created.values["id"])


def test_before_unknown_is_walked_the_same_way():
    change = {"before": {"kept": 1}, "before_unknown": {"gone": True},
              "after": None, "after_unknown": {}}
    assert plan.before_unknown_paths(change) == ("gone",)
    assert plan.after_unknown_paths(change) == ()
    marked = plan.unknown_marked(change, side="before")
    assert marked["kept"] == 1
    assert facts.is_unresolved(marked["gone"])


def test_lists_are_mirrored_element_wise():
    change = {"after": {"rule": [{"port": "22"}, {"port": "80"}]},
              "after_unknown": {"rule": [{"port": True}, {}]}}
    assert plan.after_unknown_paths(change) == ("rule[0].port",)
    marked = plan.unknown_marked(change)
    assert facts.is_unresolved(marked["rule"][0]["port"])
    assert marked["rule"][1]["port"] == "80"


# -- sensitivity -----------------------------------------------------------


def test_sensitive_paths_reads_both_mirrors():
    entry, = [e for e in PLAN["resource_changes"]
              if e["address"] == "google_service_account.etl-runner"
              and not e.get("deposed")]
    assert plan.sensitive_paths(entry) == ("private_key",)
    assert plan.sensitive_paths(entry, side="before") == ()
    deposed, = [e for e in PLAN["resource_changes"] if e.get("deposed")]
    assert plan.sensitive_paths(deposed, side="before") == ("private_key",)
    with pytest.raises(ValueError):
        plan.sensitive_paths(entry, side="sideways")


def test_no_plan_secret_reaches_any_object(read):
    rendered = _rendered(read.objects)
    for sentinel in SENTINELS:
        assert sentinel not in rendered
    assert PLAN_SECRET in PLAN_PATH.read_text(encoding="utf-8")
    # ...and the notes, which are rendered into the ledger, are clean too.
    assert PLAN_SECRET not in "\n".join(read.notes)


def test_the_sensitivity_mirror_is_carried_onto_the_object(read):
    account = read.proposed_by_address()["google_service_account.etl-runner"]
    assert account.sensitive_paths == ("private_key",)


# -- the CURRENT / PROPOSED split -----------------------------------------


def test_the_two_arms_read_one_file_and_never_share_a_source(read):
    # Its own test, because ARM 1 and ARM 3 read the SAME document: one source
    # spelling across both would make the TfObject biconditional either
    # unsatisfiable or vacuous, and would leave the merge's partition resting on
    # a `side` field nothing structurally constrains.
    assert plan.PRIOR_SOURCE != plan.PROPOSED_SOURCE
    assert plan.PROPOSED_SOURCE in facts.PROPOSED_SOURCES
    assert plan.PRIOR_SOURCE not in facts.PROPOSED_SOURCES
    assert plan.PRIOR_SOURCE in provenance.SOURCES

    assert read.current and read.proposed
    for obj in read.current:
        assert (obj.source, obj.side) == ("tfplan-prior", "current"), obj.address
    for obj in read.proposed:
        assert (obj.source, obj.side) == ("tfplan-planned", "proposed"), obj.address

    # The structural guard, in both directions.
    for source, side in ((plan.PROPOSED_SOURCE, "current"),
                         (plan.PRIOR_SOURCE, "proposed")):
        with pytest.raises(ValueError):
            TfObject(address="a.b", type="a", name="b", source=source, side=side)


def test_a_proposed_source_has_no_fidelity_rank():
    # A proposal is never ranked against reality; it is partitioned out first.
    with pytest.raises(ValueError):
        provenance.fidelity_rank(plan.PROPOSED_SOURCE)
    assert provenance.fidelity_rank(plan.PRIOR_SOURCE) \
        < provenance.fidelity_rank("tfstate")


# -- resource_drift --------------------------------------------------------


def test_resource_drift_contributes_addresses_and_zero_objects(read):
    assert read.drift_addresses == (DRIFTED,)
    # The drifted resource is ALSO in prior_state, so "no objects from drift" is
    # only checkable by value: the drift entry's `before` says priority 850 and
    # the refreshed prior state says 800. One object, carrying 800.
    assert sum(obj.address == DRIFTED for obj in read.current) == 1
    assert read.current_by_address()[DRIFTED].values["priority"] == 800
    assert PLAN["resource_drift"][0]["change"]["before"]["priority"] == 850
    assert any("resource_drift" in note and "double-count" in note
               for note in read.notes)


def test_the_drift_addresses_reach_the_ledger(read):
    builder = provenance.LedgerBuilder()
    builder.add_source(plan.source_record(read, source_id="tfplan"))
    ledger = builder.build()
    record = ledger.sources["tfplan"]
    # The existing `drift` verdict kind renders from this; no vocabulary grows.
    assert DRIFTED in record.note
    assert record.kind == plan.PRIOR_SOURCE
    assert record.scope == "partial"
    assert record.captured_at == STAMP
    assert plan.drift_note(read) == record.note


def test_a_plan_with_no_drift_carries_no_drift_note():
    result = plan.read_plan_document(_without("resource_drift"), origin="<clean>")
    assert result.drift_addresses == ()
    assert plan.drift_note(result) == ""
    assert plan.source_record(result, source_id="clean").note == ""


# -- the format gate -------------------------------------------------------


def test_a_format_version_of_two_is_refused():
    result = plan.read_plan_document(dict(PLAN, format_version="2.0"),
                                     origin="<v2>")
    assert result.ok is False
    assert result.current == () and result.proposed == ()
    assert any("2.0" in note and "major version 1" in note
               for note in result.notes)


def test_the_minor_is_not_pinned():
    result = plan.read_plan_document(dict(PLAN, format_version="1.99"),
                                     origin="<v1.99>")
    assert result.ok is True
    assert result.current and result.proposed


def test_a_document_with_no_readable_section_is_refused():
    result = plan.read_plan_document({"format_version": "1.2"}, origin="<empty>")
    assert result.ok is False
    assert plan.NOT_A_PLAN.format(path="<empty>") in result.notes


def test_the_reader_never_raises(tmp_path):
    for document in (None, [], "text", {"format_version": []},
                     {"prior_state": 7}, {"resource_changes": {}}):
        result = plan.read_plan_document(document, origin="<hostile>")
        assert result.notes, document
    missing = plan.read_plan(tmp_path / "absent.json")
    assert missing.ok is False and missing.notes


# -- ARM 4: the bare state representation ----------------------------------


def test_a_bare_state_representation_is_read_at_the_state_source():
    document = {"format_version": "1.0", "terraform_version": "1.9.5",
                "values": PLAN["prior_state"]["values"]}
    result = plan.read_plan_document(document, origin="<show-state>")
    assert result.ok is True
    assert result.arms == (plan.ARM_STATE_VALUES,)
    assert result.proposed == ()
    assert CHILD_ADDRESS in result.current_by_address()
    for obj in result.current:
        assert (obj.source, obj.side) == (plan.STATE_SOURCE, "current")
    assert plan.STATE_SOURCE == "tfstate"
    assert any(plan.ARM_STATE_VALUES in note for note in result.notes)


# -- the ONE claims path ---------------------------------------------------


#: The two claims the DELETE RULE adds and the committed plan cannot: today
#: ``tf_claims`` reads only ``change.after``, so a deleted IAM member yields
#: nothing but its type reference. Naming them is what keeps this pin honest —
#: it is a statement about the delete rule, not a licence for the extraction
#: path to drift.
DELETE_RULE_CLAIMS = [
    ("principal", "group:data-eng@acme.example",
     "google_project_iam_member.legacy-viewer.member"),
    ("role", "roles/viewer", "google_project_iam_member.legacy-viewer.role"),
]


def test_as_plan_document_preserves_the_committed_extraction_path(read):
    document = plan.as_plan_document(read.proposed)
    produced = terraform_plan_claims(document)
    committed = terraform_plan_claims(PLAN)

    # Every claim the committed fixture produces survives the round trip
    # unchanged — same kind, same value, same resource-address location.
    assert set(committed) <= set(produced)
    added = sorted(set(produced) - set(committed),
                   key=lambda claim: (claim.kind, claim.location))
    assert [(c.kind, c.value, c.location) for c in added] == DELETE_RULE_CLAIMS
    # No address is claimed twice, and the two sides cover the same resources.
    locations = [claim.location for claim in produced
                 if claim.kind == "resource_type_ref"]
    assert len(locations) == len(set(locations)) == len(read.proposed)


def test_as_plan_document_is_the_shape_the_claim_walker_reads(read):
    document = plan.as_plan_document(read.proposed)
    assert set(document) == {"format_version", "planned_values"}
    resources = document["planned_values"]["root_module"]["resources"]
    assert [entry["address"] for entry in resources] == \
        [obj.address for obj in read.proposed]
    for entry in resources:
        assert entry["mode"] == "managed"
        assert entry["type"] and entry["name"]
    indexed, = [e for e in resources if e["address"] == DRIFTED]
    assert indexed["index"] == "prod"
    assert indexed["provider_name"] == "google"
    beta, = [e for e in resources
             if e["type"] == "google_access_context_manager_service_perimeter"]
    assert beta["provider_name"] == "google-beta"


def test_an_unattributed_object_omits_provider_name():
    # The claim walker falls back to its own `google_` prefix test rather than
    # being handed a provider nobody wrote.
    obj = TfObject(address="google_project_iam_member.x", type="google_project_iam_member",
                   name="x", source=plan.PROPOSED_SOURCE, side="proposed",
                   values={"role": "roles/viewer", "member": "user:a@b.example"})
    entry, = plan.as_plan_document([obj])["planned_values"]["root_module"]["resources"]
    assert "provider_name" not in entry
    assert [c.kind for c in terraform_plan_claims(plan.as_plan_document([obj]))] \
        == ["resource_type_ref", "role", "principal"]


def test_the_frozen_claims_module_is_unweakened_and_green():
    source = CLAIMS_TF_PATH.read_text(encoding="utf-8")
    # The review gate is what enforces "unmodified"; what is checkable from
    # here is that nobody turned a pin into a no-op.
    for weakening in ("@pytest.mark", "pytest.skip", "xfail", "return  #"):
        assert weakening not in source, weakening

    spec = importlib.util.spec_from_file_location("_frozen_claims_tf",
                                                  CLAIMS_TF_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ran = 0
    for name in sorted(vars(module)):
        function = getattr(module, name)
        if not name.startswith("test_") or not callable(function):
            continue
        assert not inspect.signature(function).parameters, name
        function()
        ran += 1
    # Every test the file DECLARES ran and passed — counted off the source so a
    # deleted pin shows up as a shrinking number rather than a silent absence.
    declared = sum(line.startswith("def test_") for line in source.splitlines())
    assert ran == declared == 23
