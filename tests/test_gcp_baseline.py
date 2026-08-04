"""Acceptance for :mod:`gcp_grounding.baseline` — the current counterpart, or why not.

The load-bearing test in this file is
:func:`test_new_and_unqueried_say_different_things`. Every other test here
checks that a lookup happened; that one checks that "we looked with a complete
source and there is genuinely no predecessor" and "we did not look, or nothing
that covers this domain is entitled to prove an absence" remain two different
answers with two different messages. Collapsing them turns "we never captured
firewall rules" into "this firewall rule is brand new", and a brand-new resource
is compared against nothing at all.

Two further pins are worth naming because they guard failures that LOOK like
successes:

- :func:`test_a_side_fact_is_never_the_baseline` — one terraform address emits a
  firewall fact AND two ``network_tags`` side facts, so an unscoped locator
  lookup returns a hit, the hit looks successful, and the secondary key check
  never fires because the primary already "worked".
- :func:`test_ten_absent_targets_raise_one_key_mismatch` — a key-form regression
  makes every lookup miss CLEANLY, and every clean miss reads as a perfectly
  confident ``baseline:new``. Nothing in the ambiguity guard can see that.

The projection pin branches on each domain module's availability with plain
module-level booleans (the ``HAVE_Z3`` idiom), never ``skipif``, so it is green
before and after the ``sx-`` domain modules land: where a module is present its
own extractor is fed the projected document, and where it is not, the document's
SHAPE is pinned through ``preflight.detect_kind``, which is the same
classification those extractors are registered under.
"""

from __future__ import annotations

import os

import pytest

from gcp_grounding import (
    baseline,
    claims,
    estate,
    facts,
    identity,
    preflight,
    provenance,
    registry,
)
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.provenance import Dispute, LedgerBuilder
from gcp_grounding.reconciled import ReconciledSnapshot

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "gcp")

#: The committed terraform state. The whole tree is deliberately NOT used here:
#: with no qualifiers the HCL arm contributes rival records for the same rows,
#: and this file is pinning the PROJECTION, not the merge.
TF_STATE = os.path.join(FIXTURES, "tf", "estate.tfstate")

CAPTURED_AT = "2026-07-18T09:30:00Z"

IAM_KEY = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
FW_KEY = "projects/acme-prod/global/firewalls/allow-internal"
FW_ADDRESS = "google_compute_firewall.allow_internal"

IAM_POLICY = {"bindings": [{"role": "roles/owner",
                            "members": ["user:alice@acme.example"]}]}

FW_RECORD = {
    "network": "projects/acme-prod/global/networks/vpc-main",
    "direction": "INGRESS",
    "action": "allow",
    "priority": 1000,
    "disabled": False,
    "source_ranges": ["10.0.0.0/8"],
    "destination_ranges": [],
    "source_tags": [],
    "target_tags": [],
    "source_service_accounts": [],
    "target_service_accounts": [],
    "layer4": [{"protocol": "tcp", "ports": ["22"]}],
}

IAM_RECORD = {"bindings": [{"role": "roles/owner",
                            "members": ["user:alice@acme.example"]}]}


# -- helpers ------------------------------------------------------------------


def _snapshot(**tables):
    return GcpSnapshot(captured_at=CAPTURED_AT, **tables)


def _ledger(*, category, scope, kind="api", source_id="api-capture", keys=(),
            locators=None, taint="", disputes=()):
    """One source declaring one category at *scope*, holding *keys*."""
    builder = LedgerBuilder()
    builder.source(source_id, kind, origin=f"<{source_id}>", captured_at=CAPTURED_AT,
                   scope=scope)
    builder.declare(category, scope=scope, source_kinds=(kind,), taint=taint)
    for key in keys:
        builder.fact(category, key, source_id=source_id,
                     locator=(locators or {}).get(key, ""))
    for dispute in disputes:
        builder.dispute(dispute)
    return builder.build()


def _current(snapshot, ledger=None):
    return ReconciledSnapshot.from_snapshot(snapshot, ledger=ledger)


def _iam_hints(**kwargs):
    return baseline.Hints(target="projects/acme-prod", project="acme-prod", **kwargs)


def _of_kind(verdicts, kind):
    return [v for v in verdicts if v.kind == kind]


def _tf_object(address, name, *, resource_type="google_compute_firewall", **extra):
    values = {"name": name, "network": "vpc-main", "direction": "INGRESS",
              "priority": 1000, "disabled": False,
              "allow": [{"protocol": "tcp", "ports": ["22"]}],
              "source_ranges": ["10.0.0.0/8"]}
    values.update(extra)
    return facts.TfObject(address=address, type=resource_type,
                          name=address.split(".")[-1], source="tfplan-planned",
                          side="proposed", values=values)


def _capture():
    """The six domains' records, as the mappers produced them from the committed
    terraform fixture. Every projection pin below reads THIS, not a hand-written
    record, so a record-schema change fails here rather than rotting."""
    options = estate.CaptureOptions(
        emit=facts.TF_CATEGORIES, project="acme-prod", organization="1",
        access_policy="987", region="us-central1")
    return estate.capture(TF_STATE, options=options).snapshot


def _extractor_for(kind):
    """The extractor ``preflight`` would dispatch *kind* to, or ``None``.

    The two built-ins are resolved exactly as ``preflight._extract_claims``
    resolves them; everything else comes from the registry, which is empty until
    the domain modules land.
    """
    if kind == "iam_policy":
        return claims.iam_policy_claims
    if kind == "org_policy":
        return claims.org_policy_claims
    return registry.document_extractor(kind)


#: Domain document kind → whether an extractor for it is part of this checkout.
#: Branched on rather than skipped, per the repo idiom: an absent module is
#: asserted to degrade honestly, never quietly passed over.
HAVE_EXTRACTOR = {kind: _extractor_for(kind) is not None
                  for kind in ("firewall_rule", "firewall_policy", "security_policy",
                               "vpc_sc_perimeter", "iam_policy", "org_policy")}

#: category → (the fixture key to project, the kind the projection must emit).
#: The firewall key is ``allow-internal`` and not ``allow-health-checks``
#: BECAUSE the latter carries an empty ``layer4``: it is the empty-rule-set case
#: :func:`test_a_resolved_entry_never_carries_an_empty_rule_set` pins, not the
#: projection case.
PROJECTION_PINS = (
    ("firewall_rules", FW_KEY, "firewall_rule"),
    ("hierarchical_firewall_policies",
     "organizations/1/locations/global/firewallPolicies/fp-baseline",
     "firewall_policy"),
    ("cloud_armor_policies",
     "projects/acme-prod/global/securityPolicies/edge-waf", "security_policy"),
    ("vpc_sc_perimeters", "accessPolicies/987/servicePerimeters/prod",
     "vpc_sc_perimeter"),
    ("iam_bindings", IAM_KEY, "iam_policy"),
    ("org_policies", "projects/acme-prod|constraints/compute.disableSerialPortAccess",
     "org_policy"),
)


# -- THE distinction ----------------------------------------------------------


def test_new_and_unqueried_say_different_things():
    """``baseline:new`` and ``baseline:unqueried`` are two answers, not one.

    Asserted as its own named test because collapsing them is the single most
    dangerous thing this module could do: "we looked and there is no
    predecessor" licenses a comparison against nothing, and "we did not look"
    must not.
    """
    complete = _current(_snapshot(iam_bindings={}),
                        _ledger(category="iam_bindings", scope="complete"))
    partial = _current(_snapshot(iam_bindings={}),
                       _ledger(category="iam_bindings", scope="partial",
                               kind="tfstate", source_id="tf-state"))

    new = baseline.derive(IAM_POLICY, "iam_policy", complete, hints=_iam_hints())
    unqueried = baseline.derive(IAM_POLICY, "iam_policy", partial, hints=_iam_hints())

    new_message = _of_kind(new.verdicts, "baseline:new")[0].message
    unqueried_message = _of_kind(unqueried.verdicts, "baseline:unqueried")[0].message

    assert new_message != unqueried_message
    assert new_message not in unqueried_message
    assert unqueried_message not in new_message


def test_a_complete_source_with_no_hit_is_absent_and_baseline_new():
    current = _current(_snapshot(iam_bindings={}),
                       _ledger(category="iam_bindings", scope="complete"))

    derivation = baseline.derive(IAM_POLICY, "iam_policy", current, hints=_iam_hints())

    entry = derivation.entries[0]
    assert entry.status == "absent"
    assert entry.document is None
    verdict = _of_kind(derivation.verdicts, "baseline:new")[0]
    assert verdict.status == "unverified"
    assert "api-capture" in verdict.message


def test_a_partial_source_with_no_hit_is_unqueried():
    current = _current(_snapshot(iam_bindings={}),
                       _ledger(category="iam_bindings", scope="partial",
                               kind="tfstate", source_id="tf-state"))

    derivation = baseline.derive(IAM_POLICY, "iam_policy", current, hints=_iam_hints())

    entry = derivation.entries[0]
    assert entry.status == "unqueried"
    verdict = _of_kind(derivation.verdicts, "baseline:unqueried")[0]
    assert "tf-state" in verdict.message
    assert "not evidence" in verdict.message.lower()


def test_an_undeclared_source_with_no_hit_is_also_unqueried():
    """The case the scope lattice ADDED: covered, facts resolve, drift is
    computed — and the right to conclude "therefore it does not exist" is
    withheld. Asserted separately from the partial case because ``undeclared``
    is the default a snapshot copied without its sidecar falls back to, which
    is the shape most likely to reach a real gate."""
    current = _current(_snapshot(iam_bindings={}),
                       _ledger(category="iam_bindings", scope="undeclared",
                               kind="unattributed", source_id="no-sidecar"))

    derivation = baseline.derive(IAM_POLICY, "iam_policy", current, hints=_iam_hints())

    entry = derivation.entries[0]
    assert entry.status == "unqueried"
    assert entry.scope == "undeclared"
    assert _of_kind(derivation.verdicts, "baseline:unqueried")
    assert not _of_kind(derivation.verdicts, "baseline:new")


# -- targets ------------------------------------------------------------------


def test_an_iam_policy_with_no_hint_yields_no_target_and_three_remedies():
    current = _current(_snapshot(iam_bindings={IAM_KEY: IAM_RECORD}),
                       _ledger(category="iam_bindings", scope="complete",
                               keys=(IAM_KEY,)))

    derivation = baseline.derive(IAM_POLICY, "iam_policy", current,
                                 hints=baseline.Hints(source="policy.json"))

    assert derivation.entries == ()
    verdicts = _of_kind(derivation.verdicts, "baseline:target")
    assert len(verdicts) == 1
    for remedy in baseline.REMEDIES:
        assert remedy in verdicts[0].message
    assert len(baseline.REMEDIES) == 3


def test_a_filename_that_looks_like_a_resource_name_yields_no_target():
    """THE ANTI-GUESS PIN. The edited file is named after a resource that
    genuinely exists in the estate, and it still yields nothing: guessing a
    resource from a file name is exactly the near-miss that produces a confident
    comparison against the WRONG policy."""
    current = _current(_snapshot(iam_bindings={IAM_KEY: IAM_RECORD}),
                       _ledger(category="iam_bindings", scope="complete",
                               keys=(IAM_KEY,)))

    derivation = baseline.derive(
        IAM_POLICY, "iam_policy", current,
        hints=baseline.Hints(source="projects/acme-prod.iam_policy.json"))

    assert derivation.entries == ()
    assert derivation.rows() == ()
    assert [v.kind for v in derivation.verdicts] == ["baseline:target"]


def test_a_plan_yields_one_target_per_resource_and_refuses_a_counted_one():
    plan = {
        "format_version": "1.2",
        "terraform_version": "1.6.0",
        "resource_changes": [
            {"address": FW_ADDRESS, "mode": "managed",
             "type": "google_compute_firewall", "name": "allow_internal",
             "provider_name": "registry.terraform.io/hashicorp/google",
             "change": {"actions": ["update"], "after": {
                 "name": "allow-internal", "network": "vpc-main",
                 "direction": "INGRESS", "priority": 1000, "disabled": False,
                 "allow": [{"protocol": "tcp", "ports": ["22"]}],
                 "source_ranges": ["10.0.0.0/8"]}}},
            {"address": "google_org_policy_policy.vm_external_ip", "mode": "managed",
             "type": "google_org_policy_policy", "name": "vm_external_ip",
             "provider_name": "registry.terraform.io/hashicorp/google",
             "change": {"actions": ["update"], "after": {
                 "name": "projects/acme-prod/policies/compute.vmExternalIpAccess",
                 "parent": "projects/acme-prod",
                 "spec": [{"rules": [{"enforce": "TRUE"}]}]}}},
            {"address": "google_compute_firewall.counted", "mode": "managed",
             "type": "google_compute_firewall", "name": "counted",
             "provider_name": "registry.terraform.io/hashicorp/google",
             "change": {"actions": ["create"], "after": {
                 "name": "counted", "network": "vpc-main", "direction": "INGRESS",
                 "count": 2,
                 "allow": [{"protocol": "tcp", "ports": ["22"]}]}}},
        ],
    }

    targets, verdicts = baseline.targets_for(
        plan, "tf_plan", baseline.Hints(project="acme-prod"), source="plan.json")

    assert [t.key for t in targets] == [
        FW_KEY, "projects/acme-prod|constraints/compute.vmExternalIpAccess"]
    assert {t.how for t in targets} == {"tf-address"}
    assert [t.address for t in targets] == [
        FW_ADDRESS, "google_org_policy_policy.vm_external_ip"]

    # A 0..N resource set must not acquire a single-resource counterpart.
    assert "google_compute_firewall.counted" not in {t.address for t in targets}
    unresolved = _of_kind(verdicts, "baseline:unresolved")
    assert len(unresolved) == 1
    assert unresolved[0].target == "google_compute_firewall.counted"
    assert "count" in unresolved[0].message


# -- the projection -----------------------------------------------------------


@pytest.mark.parametrize("category,key,kind", PROJECTION_PINS,
                         ids=[pin[0] for pin in PROJECTION_PINS])
def test_the_projection_feeds_each_domain_its_own_spelling(category, key, kind):
    """Per domain, and never in aggregate: a record the mapper produced from the
    committed terraform fixture, projected, must be the shape that domain's
    extractor consumes.

    Without this the pair tier is DEAD for five of the six domains — fed a raw
    estate record the extractor emits a claim carrying the ``unsupported``
    payload key, the never-drop-a-rule discipline turns every auto-derived pair
    check into an ``unverified``, and the headline capability silently does
    nothing on the one path that has no baseline flag to tell you it did not
    run.
    """
    table = getattr(_capture(), category)
    assert table is not None and key in table, f"{category} lost {key}"

    document, projected_kind = baseline.project_record(category, key, table[key])

    assert projected_kind == kind
    assert document is not None
    # The entry's kind comes from the PROJECTION; detect_kind agreeing is what
    # says the projection landed in the shape the registry dispatches on.
    assert preflight.detect_kind(document) == kind
    assert baseline.rule_count(kind, document) > 0

    extractor = _extractor_for(kind)
    assert (extractor is not None) == HAVE_EXTRACTOR[kind]
    if extractor is None:
        return
    extracted = list(extractor(document))
    assert extracted, f"{kind} extracted no claim from its own projected document"
    for claim in extracted:
        assert "unsupported" not in claim.fields(), (
            f"{kind} read the projection as unsupported content: {claim}")


def test_a_resolved_entry_never_carries_an_empty_rule_set():
    """THE NEGATIVE PIN. An empty baseline makes every widening trivially
    provable, which manufactures a confident block out of a record that simply
    had nothing in it — so an empty rule set resolves ``opaque``, never
    ``resolved``."""
    snapshot = _capture()
    resolved = 0
    for category, _key, _kind in PROJECTION_PINS:
        table = getattr(snapshot, category)
        for key in table:
            target = baseline.TargetRef(category=category, key=key, how="document-name")
            entry, ambiguity = baseline.resolve(target, snapshot, None)
            assert not ambiguity
            if entry.status == "resolved":
                resolved += 1
                assert baseline.rule_count(entry.kind, entry.document) > 0
    assert resolved >= len(PROJECTION_PINS)

    # And the case that proves the guard fires rather than never being reached.
    empty = _snapshot(iam_bindings={IAM_KEY: {"bindings": []}})
    target = baseline.TargetRef(category="iam_bindings", key=IAM_KEY,
                                how="explicit-flag")
    entry, _ = baseline.resolve(target, empty, None)
    assert entry.status == "opaque"
    assert "opaque" in entry.flags
    assert baseline.rule_count(entry.kind, entry.document) == 0


# -- matching -----------------------------------------------------------------


def test_a_side_fact_is_never_the_baseline():
    """One address, three facts, two of them ``network_tags`` side facts.

    Asserted directly because the unscoped lookup would look SUCCESSFUL: it
    returns a hit, the hit is a real fact, and the secondary key check never
    fires to catch it because the primary already answered.
    """
    builder = LedgerBuilder()
    builder.source("tf-state", "tfstate", origin="<tfstate>",
                   captured_at=CAPTURED_AT, scope="partial")
    builder.declare("firewall_rules", scope="partial", source_kinds=("tfstate",))
    builder.declare("network_tags", scope="partial", source_kinds=("tfstate",))
    builder.fact("firewall_rules", FW_KEY, source_id="tf-state", locator=FW_ADDRESS)
    builder.fact("network_tags", "web", source_id="tf-state", locator=FW_ADDRESS)
    builder.fact("network_tags", "bastion", source_id="tf-state", locator=FW_ADDRESS)
    ledger = builder.build()

    assert len(ledger.by_locator(FW_ADDRESS)) == 3
    assert ledger.by_locator(FW_ADDRESS, category="firewall_rules") == {
        ("firewall_rules", FW_KEY)}

    snapshot = _snapshot(firewall_rules={FW_KEY: FW_RECORD},
                         network_tags=frozenset({"web", "bastion"}))
    target = baseline.TargetRef(category="firewall_rules", key=FW_KEY,
                                how="tf-address", address=FW_ADDRESS)

    entry, ambiguity = baseline.resolve(target, snapshot, ledger)

    assert not ambiguity
    assert entry.status == "resolved"
    assert entry.key == FW_KEY
    assert entry.kind == "firewall_rule"
    assert entry.document["kind"] == "compute#firewall"
    assert "web" not in str(entry.document)


def test_a_primary_and_a_secondary_on_different_keys_is_ambiguous():
    other = "projects/acme-prod/global/firewalls/allow-internal-v2"
    builder = LedgerBuilder()
    builder.source("tf-state", "tfstate", origin="<tfstate>",
                   captured_at=CAPTURED_AT, scope="partial")
    builder.declare("firewall_rules", scope="partial", source_kinds=("tfstate",))
    builder.fact("firewall_rules", FW_KEY, source_id="tf-state", locator=FW_ADDRESS)
    builder.fact("firewall_rules", other, source_id="tf-state",
                 locator="google_compute_firewall.v2")
    ledger = builder.build()
    snapshot = _snapshot(firewall_rules={FW_KEY: FW_RECORD, other: FW_RECORD})

    # The address names one row; the resource's own attributes name the other.
    target = baseline.TargetRef(category="firewall_rules", key=other,
                                how="tf-address", address=FW_ADDRESS)
    entry, ambiguity = baseline.resolve(target, snapshot, ledger)

    assert entry.document is None
    assert len(ambiguity) == 1
    assert ambiguity[0].kind == "baseline:ambiguous"
    assert ambiguity[0].status == "unverified"
    assert FW_KEY in ambiguity[0].message and other in ambiguity[0].message


def test_a_renamed_resource_resolves_through_the_secondary():
    """The address moved, the identity did not — so the ATTRIBUTES identified
    it, and ``how`` says so rather than claiming an address match."""
    ledger = _ledger(category="firewall_rules", scope="partial", kind="tfstate",
                     source_id="tf-state", keys=(FW_KEY,),
                     locators={FW_KEY: "google_compute_firewall.old_name"})
    snapshot = _snapshot(firewall_rules={FW_KEY: FW_RECORD})

    target = baseline.TargetRef(category="firewall_rules", key=FW_KEY,
                                how="tf-address",
                                address="google_compute_firewall.new_name")
    entry, ambiguity = baseline.resolve(target, snapshot, ledger)

    assert not ambiguity
    assert entry.status == "resolved"
    assert entry.key == FW_KEY
    assert entry.how == "tf-attributes"
    assert entry.target.how == "tf-address"


def test_ten_absent_targets_raise_one_key_mismatch():
    """THE SYSTEMATIC-MISS DIAGNOSTIC, and the failure ``baseline:ambiguous``
    structurally cannot catch: a key-form regression makes every lookup miss
    CLEANLY, so ten confident ``baseline:new`` answers arrive with nothing at
    all to say they are wrong."""
    held = "projects/acme-prod/global/firewalls/allow-internal"
    snapshot = _snapshot(firewall_rules={held: FW_RECORD})
    ledger = _ledger(category="firewall_rules", scope="complete", keys=(held,))
    objects = tuple(_tf_object(f"google_compute_firewall.r{i}", f"missing-{i}")
                    for i in range(10))

    derivation = baseline.derive(
        None, None, _current(snapshot, ledger),
        hints=baseline.Hints(objects=objects, project="acme-prod"))

    assert len(derivation.entries) == 10
    assert {e.status for e in derivation.entries} == {"absent"}
    mismatches = _of_kind(derivation.verdicts, "baseline:key-mismatch")
    assert len(mismatches) == 1
    message = mismatches[0].message
    assert mismatches[0].status == "unverified"
    assert mismatches[0].target == "firewall_rules"
    assert "projects/acme-prod/global/firewalls/missing-0" in message
    assert held in message
    assert "10" in message
    # It never replaces the per-target verdicts and never changes a status.
    assert len(_of_kind(derivation.verdicts, "baseline:new")) == 10


def test_the_diagnostic_stays_quiet_when_the_source_holds_nothing():
    """A complete source that holds NO rows of its own is a genuinely empty
    estate, not a key-form disagreement, so there is nothing to diagnose."""
    snapshot = _snapshot(firewall_rules={})
    ledger = _ledger(category="firewall_rules", scope="complete")
    objects = tuple(_tf_object(f"google_compute_firewall.r{i}", f"missing-{i}")
                    for i in range(10))

    derivation = baseline.derive(
        None, None, _current(snapshot, ledger),
        hints=baseline.Hints(objects=objects, project="acme-prod"))

    assert {e.status for e in derivation.entries} == {"absent"}
    assert not _of_kind(derivation.verdicts, "baseline:key-mismatch")


# -- statuses and provenance --------------------------------------------------


def test_every_status_maps_to_an_unverified_verdict():
    """ALL ``unverified``, so no baseline status ever fails the gate by itself:
    a finding is something a CHECK says, and a baseline status is only ever a
    statement about what the check was given."""
    assert set(baseline.STATUS_KINDS) == set(baseline.RESOLUTION_STATUSES)
    assert len(set(baseline.STATUS_KINDS.values())) == len(baseline.RESOLUTION_STATUSES)

    target = baseline.TargetRef(category="iam_bindings", key=IAM_KEY,
                                how="explicit-flag")
    for status in baseline.RESOLUTION_STATUSES:
        verdict = baseline.status_verdict(
            baseline.BaselineEntry(target=target, status=status, key=IAM_KEY))
        assert verdict.status == "unverified", status
        assert verdict.kind == baseline.STATUS_KINDS[status]
        assert verdict.target == IAM_KEY


def test_an_explicit_baseline_wins_by_precedence_and_appears_in_provenance():
    """An explicit baseline is not a second code path: it is loaded into an
    ``explicit-baseline`` source BEFORE ``derive`` runs, wins by ordinary
    fidelity precedence, and shows up in the provenance rows like any other
    source. ``derive`` itself never opens a file."""
    assert (provenance.fidelity_rank("explicit-baseline")
            > provenance.fidelity_rank("api"))

    typed = {"bindings": [{"role": "roles/viewer",
                           "members": ["user:alice@acme.example"]}]}
    builder = LedgerBuilder()
    builder.source("api-capture", "api", origin="<api>", captured_at=CAPTURED_AT,
                   scope="complete")
    builder.source("baseline.json", "explicit-baseline", origin="baseline.json",
                   captured_at=CAPTURED_AT, scope="complete")
    builder.declare("iam_bindings", scope="complete",
                    source_kinds=("api", "explicit-baseline"))
    builder.fact("iam_bindings", IAM_KEY, source_id="baseline.json")
    builder.alternate("iam_bindings", IAM_KEY, source_id="api-capture",
                      record=IAM_RECORD, reason="lost to 'baseline.json'")
    builder.dispute(Dispute(category="iam_bindings", key=IAM_KEY, field="bindings",
                            left="roles/viewer", right="roles/owner"))
    ledger = builder.build()
    current = _current(_snapshot(iam_bindings={IAM_KEY: typed}), ledger)

    derivation = baseline.derive(IAM_POLICY, "iam_policy", current, hints=_iam_hints())

    entry = derivation.entries[0]
    assert entry.source_id == "baseline.json"
    assert entry.status == "conflict"
    # A conflict KEEPS the chosen document and carries every conflicting fact.
    assert entry.document == typed
    assert [c.source_id for c in entry.others] == ["api-capture"]
    assert entry.others[0].record == IAM_RECORD

    row = derivation.rows()[0]
    assert row["source"] == "baseline.json"
    assert row["others"] == ("api-capture",)
    assert row["status"] == "conflict"
    assert row["how"] == "explicit-flag"
    assert _of_kind(derivation.verdicts, "baseline:conflict")[0].status == "unverified"


def test_no_current_state_is_unqueried_and_never_new():
    """The gate that configures nothing must get honest ignorance, not a clean
    bill of health."""
    derivation = baseline.derive(IAM_POLICY, "iam_policy", None, hints=_iam_hints())

    assert [e.status for e in derivation.entries] == ["unqueried"]
    assert not _of_kind(derivation.verdicts, "baseline:new")
    assert derivation.notes


def test_derive_never_raises_on_a_target_it_cannot_key():
    """An unresolved target part yields no lookup and one verdict — never a key
    built from an assumed qualifier."""
    current = _current(_snapshot(firewall_rules={FW_KEY: FW_RECORD}),
                       _ledger(category="firewall_rules", scope="complete",
                               keys=(FW_KEY,)))

    derivation = baseline.derive({"kind": "compute#firewall",
                                  "name": "allow-internal",
                                  "network": "vpc-main",
                                  "allowed": [{"IPProtocol": "tcp"}]},
                                 "firewall_rule", current,
                                 hints=baseline.Hints(source="fw.json"))

    assert derivation.entries == ()
    assert [v.kind for v in derivation.verdicts] == ["baseline:unresolved"]
    assert derivation.verdicts[0].status == "unverified"


def test_a_document_that_names_itself_needs_no_hint():
    current = _current(_snapshot(firewall_rules={FW_KEY: FW_RECORD}),
                       _ledger(category="firewall_rules", scope="complete",
                               keys=(FW_KEY,)))

    derivation = baseline.derive({"kind": "compute#firewall",
                                  "name": "allow-internal",
                                  "network": "vpc-main",
                                  "allowed": [{"IPProtocol": "tcp"}]},
                                 "firewall_rule", current,
                                 hints=baseline.Hints(project="acme-prod"))

    entry = derivation.entries[0]
    assert entry.status == "resolved"
    assert entry.how == "document-name"
    assert entry.key == FW_KEY
    assert entry.kind == "firewall_rule"


def test_the_hint_order_is_flag_then_config_then_tool_input():
    current = _current(_snapshot(iam_bindings={}),
                       _ledger(category="iam_bindings", scope="complete"))
    config = {"policy.json": "projects/acme-config"}
    tool = {"resource": "projects/acme-tool"}

    both = baseline.derive(IAM_POLICY, "iam_policy", current,
                           hints=baseline.Hints(target="projects/acme-flag",
                                                targets=config, tool_input=tool,
                                                source="policy.json"))
    assert both.entries[0].how == "explicit-flag"
    assert both.entries[0].target.key.endswith("projects/acme-flag")

    mapped = baseline.derive(IAM_POLICY, "iam_policy", current,
                             hints=baseline.Hints(targets=config, tool_input=tool,
                                                  source="policy.json"))
    assert mapped.entries[0].how == "config-map"
    assert mapped.entries[0].target.key.endswith("projects/acme-config")

    supplied = baseline.derive(IAM_POLICY, "iam_policy", current,
                               hints=baseline.Hints(tool_input=tool,
                                                    source="policy.json"))
    assert supplied.entries[0].how == "tool-input"
    assert supplied.entries[0].target.key.endswith("projects/acme-tool")


def test_the_how_vocabulary_is_closed():
    """``how`` is carried into explain output, so an operator can see WHY two
    documents were thought to be counterparts — an unnamed reason is a
    comparison nobody can audit."""
    assert baseline.HOWS == ("explicit-flag", "config-map", "tool-input",
                             "document-name", "tf-address", "tf-attributes")
    with pytest.raises(ValueError, match="how"):
        baseline.TargetRef(category="iam_bindings", key=IAM_KEY, how="filename")


def test_a_target_key_is_built_by_the_one_identity_module():
    """The proposal side and the capture side share one key builder, so the two
    can never drift into two spellings of one resource."""
    current = _current(_snapshot(iam_bindings={}),
                       _ledger(category="iam_bindings", scope="complete"))

    derivation = baseline.derive(IAM_POLICY, "iam_policy", current,
                                 hints=_iam_hints())

    assert derivation.entries[0].target.key == identity.canonical_key(
        "iam_bindings", name="projects/acme-prod")
