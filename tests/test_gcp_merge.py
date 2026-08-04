"""Acceptance for `gcp_grounding.merge` — THE one resolution engine.

The headline pin is `test_precedence_selects_a_value_never_suppresses_a_finding`:
the SAME disagreement run under two opposite precedences selects opposite values
and BOTH report it. Everything else in this file exists so that pin cannot be
satisfied by an engine that is wrong somewhere else.

No capability branch is needed here: `merge` is pure stdlib and imports neither
z3 nor any GCP SDK, so every assertion below runs in every environment.
"""

from __future__ import annotations

import ast
import itertools

import pytest

from gcp_grounding import facts, identity, merge, provenance
from gcp_grounding.provenance import SourceLedger, SourceRecord

FW = "firewall_rules"
FW_KEY = "projects/acme-prod/global/firewalls/allow-ssh"
FW_KEY_2 = "projects/acme-prod/global/firewalls/deny-ssh"
ARMOR = "cloud_armor_policies"
ARMOR_KEY = "projects/acme-prod/global/securityPolicies/edge-waf"
NET = "networks"
SA = "service_accounts"


def fact(category, key, record=None, *, source, origin="", address="", fragment="",
         side="current", unresolved=()):
    return facts.Fact(category=category, key=key, record=record, source=source,
                      side=side, origin=origin or source, address=address,
                      fragment=fragment, unresolved=unresolved)


def api(scope="complete", source_id="api", captured_at="2026-03-01T00:00:00Z"):
    return SourceRecord(source_id=source_id, kind="api", scope=scope,
                        captured_at=captured_at, origin="compute.firewalls.list")


def state(source_id="state-a", scope="partial", captured_at="2026-02-01T00:00:00Z"):
    return SourceRecord(source_id=source_id, kind="tfstate", scope=scope,
                        captured_at=captured_at, origin=f"{source_id}.tfstate")


def hcl(source_id="hcl", scope="partial", captured_at="2026-01-01T00:00:00Z"):
    return SourceRecord(source_id=source_id, kind="hcl", scope=scope,
                        captured_at=captured_at, origin="main.tf")


# -- step 1: the proposal partition -------------------------------------------


def test_a_proposed_fact_is_dropped_with_a_note_and_never_resolves():
    """The second enforcement point: a proposal can never be laundered into
    current state, whichever proposed spelling it wears."""
    current = fact(FW, FW_KEY, {"action": "allow"}, source="tfstate",
                   origin="state-a", address="google_compute_firewall.allow_ssh")
    planned = fact(FW, FW_KEY, {"action": "allow", "source_ranges": ["0.0.0.0/0"]},
                   source="tfplan-planned", origin="plan", side="proposed",
                   address="google_compute_firewall.allow_ssh")
    proposed_hcl = fact(NET, "projects/acme-prod/global/networks/vpc",
                        source="hcl-proposed", origin="proposal.tf", side="proposed")

    result = merge.resolve([current, planned, proposed_hcl], sources=[state()])

    assert {id(d.fact) for d in result.dropped} == {id(planned), id(proposed_hcl)}
    for drop in result.dropped:
        assert merge.PROPOSED_DROP_REASON in drop.note
    # It never appears in a resolution, and the current-state value survives
    # unmodified by the proposal beside it.
    resolution = result.resolution(FW, FW_KEY)
    assert resolution is not None
    assert resolution.record == {"action": "allow"}
    assert [id(f) for f in resolution.contributors] == [id(current)]
    assert result.resolution(NET, "projects/acme-prod/global/networks/vpc") is None


# -- step 2: the ambiguous key ------------------------------------------------


def test_an_ambiguous_key_is_kept_raw_tainted_and_disputed():
    """A bare firewall name has no project, so `identity` refuses to build a key
    for it. The fact is kept under its RAW key rather than merged onto one
    somebody guessed."""
    bare = fact(FW, "allow-ssh", {"action": "allow"}, source="tfstate",
                origin="state-a", address="google_compute_firewall.allow_ssh")

    result = merge.resolve([bare], sources=[state()])

    resolution = result.resolution(FW, "allow-ssh")
    assert resolution is not None, "the fact is KEPT under its raw key"
    assert resolution.taint == "unmergeable"
    assert resolution.origin.taint == "unmergeable"
    reason = result.unresolved_aliases[FW]["allow-ssh"]
    assert "missing_project" in reason
    unmergeable = [d for d in result.disputes if d.severity == "unmergeable"]
    assert len(unmergeable) == 1
    assert unmergeable[0].key == "allow-ssh"
    assert "missing_project" in unmergeable[0].reason


# -- step 4: fragment assembly ------------------------------------------------


def _armor_fragment(priority, action, address):
    return fact(ARMOR, ARMOR_KEY,
                {"priority": priority,
                 "rules": [{"priority": priority, "action": action}]},
                source="tfstate", origin="state-a", fragment="rules",
                address=f"google_compute_security_policy_rule.{address}")


def test_fragments_assemble_in_priority_then_address_order_and_duplicates_collapse():
    """PRIORITY FIRST, address only to break a tie. Every address below sorts
    the OPPOSITE way to its priority, so an assembler that ordered by address
    alone would produce a rule list in the wrong precedence order — and for a
    Cloud Armor or firewall policy the order IS the semantics."""
    base = fact(ARMOR, ARMOR_KEY, {"type": "CLOUD_ARMOR"}, source="tfstate",
                origin="state-a", address="google_compute_security_policy.edge")
    first = _armor_fragment(1000, "allow", "z_allow")
    second = _armor_fragment(2000, "deny(403)", "m_deny")
    duplicate = _armor_fragment(1000, "allow", "z_allow_copy")
    tie_late = _armor_fragment(3000, "deny(404)", "b_x")
    tie_early = _armor_fragment(3000, "goto_next", "a_y")

    result = merge.resolve([tie_late, second, base, duplicate, tie_early, first],
                           sources=[state()])

    record = result.resolution(ARMOR, ARMOR_KEY).record
    assert record["type"] == "CLOUD_ARMOR"
    assert record["rules"] == [
        {"priority": 1000, "action": "allow"},        # the exact duplicate collapsed
        {"priority": 2000, "action": "deny(403)"},
        {"priority": 3000, "action": "goto_next"},    # equal priority, address a_y
        {"priority": 3000, "action": "deny(404)"},    # equal priority, address b_x
    ]


def test_a_list_field_no_fragment_assembles_is_never_sorted():
    unsorted_ranges = ["10.0.0.0/8", "0.0.0.0/0", "192.168.0.0/16"]
    only = fact(FW, FW_KEY, {"action": "allow", "source_ranges": unsorted_ranges},
                source="tfstate", origin="state-a")

    result = merge.resolve([only], sources=[state()])

    assert result.resolution(FW, FW_KEY).record["source_ranges"] == unsorted_ranges


def test_fragments_with_no_base_record_assemble_onto_an_empty_record_with_a_note():
    orphan = fact(ARMOR, ARMOR_KEY, {"priority": 1000,
                                     "rules": [{"priority": 1000, "action": "allow"}]},
                  source="tfstate", origin="state-a", fragment="rules",
                  address="google_compute_security_policy_rule.a")

    result = merge.resolve([orphan], sources=[state()])

    resolution = result.resolution(ARMOR, ARMOR_KEY)
    assert resolution.record == {"rules": [{"priority": 1000, "action": "allow"}]}
    assert any("not in the same" in note for note in resolution.notes)


# -- steps 5 and 6: wholesale, and the one narrow exception -------------------


def test_the_winner_record_is_taken_wholesale():
    """A field the LOSER carried and the winner did not is ABSENT: a
    half-and-half record would describe a configuration that exists nowhere."""
    winner = fact(FW, FW_KEY, {"action": "allow", "priority": 1000},
                  source="api", origin="api")
    loser = fact(FW, FW_KEY, {"action": "allow", "priority": 1000, "disabled": False,
                              "target_tags": ["bastion"]},
                 source="tfstate", origin="state-a",
                 address="google_compute_firewall.allow_ssh")

    result = merge.resolve([winner, loser], sources=[api(), state()])

    record = result.resolution(FW, FW_KEY).record
    assert record == {"action": "allow", "priority": 1000}
    assert "target_tags" not in record
    assert result.backfilled == {}
    assert result.disputes == (), (
        "one side simply NOT CARRYING a field is an absence, which is step 8's "
        "question; a field-level dispute needs a genuine differing VALUE")
    # ...and the loser is still available WHOLE, so a pair check can be re-run.
    alternate = result.alternates[FW][FW_KEY][0]
    assert alternate.source_id == "state-a"
    assert alternate.record["target_tags"] == ["bastion"]


def test_backfill_fills_an_unresolved_winner_field_from_a_resolved_loser():
    marker = facts.Unresolved("unknown_after_apply", "network")
    missing = facts.Unresolved("interpolation", "source_ranges")
    winner = fact(FW, FW_KEY, {"action": "allow", "network": marker},
                  source="tfstate", origin="state-a", unresolved=(marker, missing),
                  address="google_compute_firewall.allow_ssh")
    loser = fact(FW, FW_KEY, {"action": "allow",
                              "network": "projects/acme-prod/global/networks/vpc",
                              "source_ranges": ["10.0.0.0/8"]},
                 source="hcl", origin="hcl", address="google_compute_firewall.allow_ssh")

    result = merge.resolve([winner, loser], sources=[state(), hcl()])

    resolution = result.resolution(FW, FW_KEY)
    assert resolution.origin.source_id == "state-a", "the winner is still the winner"
    assert resolution.record["network"] == "projects/acme-prod/global/networks/vpc"
    assert resolution.record["source_ranges"] == ["10.0.0.0/8"]
    assert resolution.backfilled == ("network", "source_ranges")
    assert result.backfilled[FW][FW_KEY] == ("network", "source_ranges")


# -- THE HEADLINE PIN ---------------------------------------------------------


def _disagreement():
    left = fact(FW, FW_KEY, {"action": "allow", "priority": 1000,
                             "source_ranges": ["10.0.0.0/8"]},
                source="api", origin="api")
    right = fact(FW, FW_KEY, {"action": "allow", "priority": 1000,
                              "source_ranges": ["0.0.0.0/0"]},
                 source="tfstate", origin="state-a",
                 address="google_compute_firewall.allow_ssh")
    return left, right


def test_precedence_selects_a_value_never_suppresses_a_finding():
    """PRECEDENCE SELECTS A VALUE, IT NEVER SUPPRESSES A FINDING.

    The same disagreement under two opposite precedences selects OPPOSITE
    values, and BOTH report it. This is the pin that stops `--precedence`
    becoming a way to silence a disagreement.
    """
    left, right = _disagreement()
    sources = [api(scope="partial"), state()]

    api_wins = merge.resolve([left, right], sources=sources,
                             policy=merge.parse_policy("api-wins"))
    tf_wins = merge.resolve([left, right], sources=sources,
                            policy=merge.parse_policy("terraform-wins"))

    api_record = api_wins.resolution(FW, FW_KEY).record
    tf_record = tf_wins.resolution(FW, FW_KEY).record
    assert api_record["source_ranges"] == ["10.0.0.0/8"]
    assert tf_record["source_ranges"] == ["0.0.0.0/0"]
    assert api_wins.resolution(FW, FW_KEY).origin.source_id == "api"
    assert tf_wins.resolution(FW, FW_KEY).origin.source_id == "state-a"

    for result in (api_wins, tf_wins):
        material = [d for d in result.disputes
                    if d.severity == "material" and d.field == "source_ranges"]
        assert len(material) == 1, "the loser is recorded whichever side wins"
        assert result.resolution(FW, FW_KEY).taint == "disputed"
        assert result.alternates[FW][FW_KEY], "the losing WHOLE record survives"


# -- step 8: existence disagreement, and its directionality -------------------


def _mixed_estate(api_scope):
    terraform_only = fact(FW, FW_KEY, {"action": "allow"}, source="tfstate",
                          origin="state-a",
                          address="google_compute_firewall.allow_ssh")
    api_only = fact(FW, FW_KEY_2, {"action": "deny"}, source="api", origin="api")
    return [terraform_only, api_only], [api(scope=api_scope), state()]


def test_terraform_only_key_absent_from_a_complete_enumeration_is_material():
    given, sources = _mixed_estate("complete")

    result = merge.resolve(given, sources=sources)

    material = [d for d in result.disputes
                if d.severity == "material" and d.key == FW_KEY]
    assert len(material) == 1
    assert "may have been destroyed or moved out of band" in material[0].reason
    resolution = result.resolution(FW, FW_KEY)
    assert resolution is not None, "the fact is KEPT"
    assert resolution.taint == "disputed"


def test_the_reverse_direction_is_unmanaged_and_never_material():
    given, sources = _mixed_estate("complete")

    result = merge.resolve(given, sources=sources)

    unmanaged = [d for d in result.disputes if d.key == FW_KEY_2]
    assert len(unmanaged) == 1
    assert unmanaged[0].severity == "unmanaged"
    assert "terraform does not manage it" in unmanaged[0].reason
    # unmanaged is normal in a partially adopted estate, so it taints nothing.
    assert result.resolution(FW, FW_KEY_2).taint == ""


def test_a_partial_enumeration_licenses_no_existence_dispute_at_all():
    given, sources = _mixed_estate("partial")

    result = merge.resolve(given, sources=sources)

    assert result.disputes == (), "absence from a partial view is not evidence"
    assert result.resolution(FW, FW_KEY) is not None
    assert result.resolution(FW, FW_KEY_2) is not None


# -- step 9: flat vocabularies, unioned under a fidelity floor ----------------


HCL_ONLY_NET = "projects/acme-prod/global/networks/vpc-declared-only"
SHARED_NET = "projects/acme-prod/global/networks/vpc-shared"
HCL_ONLY_SA = "declared-only@acme-prod.iam.gserviceaccount.com"


def _flat_facts():
    return [
        fact(NET, HCL_ONLY_NET, source="hcl", origin="hcl",
             address="google_compute_network.declared_only"),
        fact(SA, HCL_ONLY_SA, source="hcl", origin="hcl",
             address="google_service_account.declared_only"),
        fact(NET, SHARED_NET, source="hcl", origin="hcl",
             address="google_compute_network.shared"),
        fact(NET, SHARED_NET, source="tfstate", origin="state-a",
             address="google_compute_network.shared"),
    ]


@pytest.mark.parametrize("mode", merge.PRECEDENCE)
def test_flat_vocabularies_union_above_the_fidelity_floor_under_every_policy(mode):
    result = merge.resolve(_flat_facts(), sources=[hcl(), state()],
                           policy=merge.parse_policy(mode))

    # The name a source that OBSERVED reality also carries is emitted normally.
    assert result.keys_of(NET) == (SHARED_NET,)
    assert result.resolution(NET, SHARED_NET).origin.source_id == "state-a"
    assert result.resolution(NET, SHARED_NET).record is None

    # A name only CONFIGURATION carries is withheld: unioning it in would mint a
    # `grounded` for something that may never have been applied.
    assert HCL_ONLY_NET not in result.keys_of(NET)
    assert result.keys_of(SA) == ()
    assert result.declared_not_applied[NET] == (HCL_ONLY_NET,)
    assert result.declared_not_applied[SA] == (HCL_ONLY_SA,)
    withheld = [d for d in result.dropped if d.fact.key in (HCL_ONLY_NET, HCL_ONLY_SA)]
    assert len(withheld) == 2
    for drop in withheld:
        assert merge.DECLARED_NOT_APPLIED_REASON in drop.note


def test_default_category_precedence_holds_no_flat_vocabulary_and_no_resource_types():
    """Flat vocabularies never consult precedence (step 9 unions them), and
    `resource_types` is not a terraform-producible category at all."""
    assert set(merge.DEFAULT_CATEGORY_PRECEDENCE).isdisjoint(facts.FLAT_CATEGORIES)
    assert "resource_types" not in merge.DEFAULT_CATEGORY_PRECEDENCE
    assert "resource_types" in facts.EXCLUDED_CATEGORIES
    assert merge.DEFAULT_CATEGORY_PRECEDENCE == {"iam_bindings": "api-wins"}


# -- step 9a: the systematic-miss diagnostic ----------------------------------


def _two_state_files(left_project, right_project):
    given = []
    for source_id, project in (("state-a", left_project), ("state-b", right_project)):
        for name in ("allow-ssh", "deny-ssh"):
            given.append(fact(FW, f"projects/{project}/global/firewalls/{name}",
                              {"action": "allow"}, source="tfstate", origin=source_id,
                              address=f"google_compute_firewall.{name}"))
    return given, [state("state-a"), state("state-b")]


def test_a_project_number_versus_id_key_mismatch_emits_one_diagnostic():
    """`identity` deliberately keeps a project NUMBER and a project id distinct
    when the alias is unknown, so two layers can key one estate two ways and
    produce zero disputes and zero drift. That silence is the finding."""
    given, sources = _two_state_files("123456789012", "acme-prod")

    result = merge.resolve(given, sources=sources)

    assert result.disputes == (), "the silent failure this diagnostic exists for"
    verdicts = [v for v in result.verdicts if v.kind == merge.KEY_MISMATCH_KIND]
    assert len(verdicts) == 1
    verdict = verdicts[0]
    assert verdict.status == "unverified"
    assert verdict.target == FW
    for expected in ("state-a", "state-b", "zero keys matched",
                     "projects/123456789012/global/firewalls/allow-ssh",
                     "projects/acme-prod/global/firewalls/allow-ssh"):
        assert expected in verdict.message


def test_a_key_nobody_could_build_is_not_a_canonical_key():
    """Step 9a compares CANONICAL key sets. A raw key kept under step 2 is not
    one, so it can neither pad a source up to `MIN_KEYS_FOR_MISMATCH` nor
    manufacture an empty intersection — the unbuildable key is already reported
    as an unmergeable dispute, and reporting it twice under a diagnostic about
    key FORMS would name the wrong failure."""
    left = [fact(FW, f"projects/123456789012/global/firewalls/{name}",
                 {"action": "allow"}, source="tfstate", origin="state-a")
            for name in ("allow-ssh", "deny-ssh")]
    right = [
        fact(FW, "projects/acme-prod/global/firewalls/allow-ssh", {"action": "allow"},
             source="tfstate", origin="state-b"),
        fact(FW, "allow-ssh", {"action": "allow"}, source="tfstate", origin="state-b"),
    ]

    result = merge.resolve(left + right,
                           sources=[state("state-a"), state("state-b")])

    assert len(result.unresolved_aliases[FW]) == 1
    assert [v for v in result.verdicts if v.kind == merge.KEY_MISMATCH_KIND] == [], \
        "'state-b' contributed ONE canonical key, below MIN_KEYS_FOR_MISMATCH"
    assert merge.MIN_KEYS_FOR_MISMATCH == 2


def test_matching_key_forms_emit_no_diagnostic():
    given, sources = _two_state_files("acme-prod", "acme-prod")

    result = merge.resolve(given, sources=sources)

    assert [v for v in result.verdicts if v.kind == merge.KEY_MISMATCH_KIND] == []
    assert result.keys_of(FW) == (
        "projects/acme-prod/global/firewalls/allow-ssh",
        "projects/acme-prod/global/firewalls/deny-ssh")


# -- one address is many facts ------------------------------------------------


def test_two_state_files_at_one_address_are_both_retained_and_both_indexed():
    """A single-valued address index would silently choose one row. `by_locator`
    is a SET for exactly this reason."""
    address = "google_compute_firewall.allow_ssh"
    left = fact(FW, "projects/acme-prod/global/firewalls/allow-ssh",
                {"action": "allow"}, source="tfstate", origin="state-a",
                address=address)
    right = fact(FW, "projects/acme-dev/global/firewalls/allow-ssh",
                 {"action": "allow"}, source="tfstate", origin="state-b",
                 address=address)

    result = merge.resolve([left, right],
                           sources=[state("state-a"), state("state-b")])

    assert len(result.resolutions) == 2
    assert result.resolution(FW, left.key).origin.source_id == "state-a"
    assert result.resolution(FW, right.key).origin.source_id == "state-b"
    ledger = SourceLedger(sources={"state-a": state("state-a"),
                                   "state-b": state("state-b")},
                          facts=result.origins())
    assert ledger.by_locator(address) == {(FW, left.key), (FW, right.key)}
    assert len(ledger.by_locator(address, category=FW)) == 2


# -- step 10 and 11: order independence, identity, determinism ----------------


def _three_source_facts():
    return {
        "api": [
            fact(FW, FW_KEY, {"action": "allow", "priority": 1000,
                              "source_ranges": ["10.0.0.0/8"]},
                 source="api", origin="api"),
            fact(NET, SHARED_NET, source="api", origin="api"),
        ],
        "state-a": [
            fact(FW, FW_KEY, {"action": "allow", "priority": 1000,
                              "source_ranges": ["0.0.0.0/0"]},
                 source="tfstate", origin="state-a",
                 address="google_compute_firewall.allow_ssh"),
            fact(NET, SHARED_NET, source="tfstate", origin="state-a",
                 address="google_compute_network.shared"),
        ],
        "hcl": [
            fact(FW, FW_KEY_2, {"action": "deny", "priority": 900},
                 source="hcl", origin="hcl",
                 address="google_compute_firewall.deny_ssh"),
            fact(NET, HCL_ONLY_NET, source="hcl", origin="hcl"),
        ],
    }


def test_merging_three_sources_in_all_six_orders_is_identical():
    groups = _three_source_facts()
    sources = [api(scope="partial"), state("state-a"), hcl()]
    baseline = None
    orders = list(itertools.permutations(sorted(groups)))
    assert len(orders) == 6
    for order in orders:
        given = [f for name in order for f in groups[name]]
        result = merge.resolve(given, sources=sources)
        if baseline is None:
            baseline = result
            continue
        assert result.resolutions == baseline.resolutions
        assert result.disputes == baseline.disputes
        assert result.scopes == baseline.scopes
        assert result.declared_not_applied == baseline.declared_not_applied
        assert result.notes == baseline.notes


def test_every_input_fact_is_accounted_for_in_exactly_one_place():
    groups = _three_source_facts()
    given = [f for name in sorted(groups) for f in groups[name]]
    given.append(fact(FW, FW_KEY, {"action": "allow"}, source="tfplan-planned",
                      origin="plan", side="proposed"))

    result = merge.resolve(given, sources=[api(scope="partial"), state("state-a"),
                                           hcl()])

    seen = [id(f) for r in result.resolutions for f in r.contributors]
    seen += [id(d.fact) for d in result.dropped]
    assert sorted(seen) == sorted(id(f) for f in given)
    assert len(seen) == len(set(seen)), "exactly one place, never two"


def test_a_single_source_merge_is_an_exact_identity():
    record = {"action": "allow", "priority": 1000,
              "source_ranges": ["10.0.0.0/8", "0.0.0.0/0"]}
    given = [
        fact(FW, FW_KEY, record, source="api", origin="api"),
        fact(NET, SHARED_NET, source="api", origin="api"),
    ]
    source = api(captured_at="2026-03-01T00:00:00Z")

    result = merge.resolve(given, sources=[source])

    assert result.captured_at == "2026-03-01T00:00:00Z"
    assert {r.category for r in result.resolutions} == {FW, NET}
    assert result.resolution(FW, FW_KEY).record is record, "not even copied"
    assert result.resolution(NET, SHARED_NET).record is None
    assert result.disputes == ()
    assert result.dropped == ()
    assert result.alternates == {}


def test_merged_captured_at_is_the_minimum_over_contributors():
    given = [
        fact(FW, FW_KEY, {"action": "allow"}, source="api", origin="api"),
        fact(FW, FW_KEY_2, {"action": "deny"}, source="tfstate", origin="state-a"),
    ]

    result = merge.resolve(given, sources=[
        api(captured_at="2026-03-01T00:00:00Z"),
        state(captured_at="2026-01-15T00:00:00Z")])

    assert result.captured_at == "2026-01-15T00:00:00Z"


def test_scopes_compose_through_the_lattice_and_terraform_caps_at_partial():
    given, sources = _mixed_estate("complete")

    result = merge.resolve(given, sources=sources)

    scope = result.scopes[FW]
    assert scope.source_kinds == ("api", "tfstate")
    assert scope.scope == "partial", "terraform covers only what terraform manages"
    assert provenance.require_complete(
        SourceLedger(categories=result.scopes), FW) is not None


# -- the precedence surface ---------------------------------------------------


def test_parse_policy_merges_onto_the_defaults():
    bare = merge.parse_policy("terraform-wins")
    assert bare.default == "terraform-wins"
    assert bare.categories == {"iam_bindings": "api-wins"}, "the default survives"

    assignments = merge.parse_policy("org_policies=terraform-wins")
    assert assignments.default == merge.DEFAULT_PRECEDENCE
    assert assignments.categories == {"iam_bindings": "api-wins",
                                      "org_policies": "terraform-wins"}

    both = merge.parse_policy("api-wins, iam_bindings=terraform-wins")
    assert both.default == "api-wins"
    assert both.categories["iam_bindings"] == "terraform-wins"
    assert both.for_category(FW) == "api-wins"
    assert both.for_category("iam_bindings") == "terraform-wins"

    assert merge.parse_policy("").default == merge.DEFAULT_PRECEDENCE


@pytest.mark.parametrize("spec,token", [
    ("nonsense", "nonsense"),
    ("api-wins,whatever", "whatever"),
    ("firewall_rules=nope", "firewall_rules=nope"),
    ("not_a_category=api-wins", "not_a_category=api-wins"),
])
def test_parse_policy_raises_naming_the_offending_token(spec, token):
    with pytest.raises(ValueError) as caught:
        merge.parse_policy(spec)
    assert repr(token) in str(caught.value)


@pytest.mark.parametrize("weak,strong", list(
    itertools.combinations([s for s in provenance.SOURCES], 2)))
def test_api_wins_coincides_with_highest_fidelity_wins_for_every_source_pair(weak, strong):
    """The design's justification for the DEFAULT, pinned rather than assumed:
    `highest-fidelity-wins` degrades to `api-wins` for the api-plus-terraform
    pair while still ordering `tfstate` above `hcl` when there is no API at all.

    That degradation is a property of `provenance.SOURCES`' ORDER, so reordering
    it fails here rather than silently changing what `--precedence api-wins`
    means to somebody's CI.
    """
    given = [
        fact(FW, FW_KEY, {"action": "allow", "priority": 1}, source=weak,
             origin=f"src-{weak}"),
        fact(FW, FW_KEY, {"action": "allow", "priority": 2}, source=strong,
             origin=f"src-{strong}"),
    ]
    sources = [SourceRecord(source_id=f"src-{kind}", kind=kind, scope="undeclared")
               for kind in (weak, strong)]

    by_fidelity = merge.resolve(given, sources=sources,
                                policy=merge.parse_policy("highest-fidelity-wins"))
    by_api = merge.resolve(given, sources=sources,
                           policy=merge.parse_policy("api-wins"))

    assert by_fidelity.resolution(FW, FW_KEY).origin.source_id == f"src-{strong}"
    assert by_api.resolution(FW, FW_KEY).origin.source_id == f"src-{strong}"


def test_terraform_wins_prefers_state_then_prior_then_hcl():
    """...and then falls back to fidelity, which is what makes it a total order
    rather than three rules and a coin toss."""
    order = ("tfstate", "tfplan-prior", "hcl", "api")
    for index, winner in enumerate(order[:-1]):
        for loser in order[index + 1:]:
            given = [
                fact(FW, FW_KEY, {"action": "allow", "priority": 1}, source=winner,
                     origin=f"src-{winner}"),
                fact(FW, FW_KEY, {"action": "allow", "priority": 2}, source=loser,
                     origin=f"src-{loser}"),
            ]
            sources = [SourceRecord(source_id=f"src-{kind}", kind=kind,
                                    scope="undeclared") for kind in (winner, loser)]
            result = merge.resolve(given, sources=sources,
                                   policy=merge.parse_policy("terraform-wins"))
            assert result.resolution(FW, FW_KEY).origin.source_id == f"src-{winner}", \
                f"terraform-wins must prefer {winner!r} over {loser!r}"


def test_precedence_policy_validates_its_own_fields():
    with pytest.raises(ValueError, match="not one of"):
        merge.PrecedencePolicy(default="whatever")
    with pytest.raises(ValueError, match="not one of"):
        merge.PrecedencePolicy(categories={"firewall_rules": "whatever"})
    with pytest.raises(ValueError, match="not an estate category"):
        merge.PrecedencePolicy(categories={"nope": "api-wins"})
    assert set(merge.PrecedencePolicy().categories) <= set(identity.SPECS)


def test_require_agreement_escalates_and_does_not_drop_the_key():
    """`require-agreement` is exactly `highest-fidelity-wins` plus escalation.
    It does NOT drop the disputed key: dropping it from a complete category
    would let the merged view prove an absence that is not proven."""
    left, right = _disagreement()

    result = merge.resolve([left, right], sources=[api(), state()],
                           policy=merge.parse_policy("require-agreement"))

    resolution = result.resolution(FW, FW_KEY)
    assert resolution is not None, "the key is KEPT"
    assert resolution.record["source_ranges"] == ["10.0.0.0/8"], "highest fidelity"
    escalations = [v for v in result.verdicts if v.kind == "drift:material"]
    assert len(escalations) == 1
    assert escalations[0].status == "contradicted"
    assert escalations[0].target == f"{FW}/{FW_KEY}"

    # ...and the same disagreement under the default escalates nothing.
    default = merge.resolve([left, right], sources=[api(), state()])
    assert [v for v in default.verdicts if v.kind == "drift:material"] == []
    assert [d for d in default.disputes if d.severity == "material"]


# -- the module contract ------------------------------------------------------


def test_the_module_docstring_leads_with_the_headline_invariant():
    first = merge.__doc__.strip().splitlines()[0]
    assert first == "PRECEDENCE SELECTS A VALUE, IT NEVER SUPPRESSES A FINDING."


def test_merge_is_pure_and_never_reaches_the_estate_model():
    """PURE: no snapshot, no I/O, no clock. Asserted over the module's own
    import statements, so an import added later fails here rather than turning
    the one order-independent layer into one that reads a file."""
    with open(merge.__file__, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(f"{node.module or ''}.{a.name}" for a in node.names)
    for banned in ("knowledge", "os", "io", "json", "time", "datetime", "pathlib",
                   "random", "gcp_grounding.knowledge", ".knowledge", ".fetch"):
        assert banned not in imported, f"merge must not import {banned!r}"
