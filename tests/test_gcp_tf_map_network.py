"""VPC firewall, hierarchical firewall policy and Cloud Armor, mapped to estate
records.

THE HEADLINE PIN is asserted against the LOADED ``estate_snapshot.json`` rather
than against hand-copied literals, so a change to the record schema fails HERE
instead of drifting: the mapper and the estate table are two ends of one
contract, and a test that spelled the record out itself would only ever pin the
mapper against yesterday's copy of it.

``terraform`` is not installed on this machine and nothing here needs it. The
two drivers below are NOT readers — ``tfsource/state.py`` and ``tfsource/hcl.py``
are their own tasks and this module must keep passing before either exists — they
are just enough to hand the mappers the COMMITTED corpus in the plan-JSON
encoding every reader is required to produce, so these assertions move when the
fixtures move.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding import facts, knowledge
from gcp_grounding.tfsource import map_network, mapping

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
ESTATE = FIXTURES / "estate_snapshot.json"
STATE = FIXTURES / "tf" / "estate.tfstate"
MAIN_TF = FIXTURES / "tf" / "hcl" / "main.tf"

#: The context the committed corpus is captured with: acme-prod in
#: organizations/1, exactly as the fixture headers say.
CTX = mapping.MapContext(project="acme-prod", region="us-central1",
                         organization="1", access_policy="987")

#: The six records the task pins, by the estate key each is stored under.
FIREWALL = "projects/acme-prod/global/firewalls/"
HEADLINE = (
    ("firewall_rules", f"{FIREWALL}allow-internal"),
    ("firewall_rules", f"{FIREWALL}deny-ssh-external"),
    ("firewall_rules", f"{FIREWALL}allow-iap-ssh"),
    ("firewall_rules", f"{FIREWALL}allow-health-checks"),
    ("hierarchical_firewall_policies",
     "organizations/1/locations/global/firewallPolicies/fp-baseline"),
    ("cloud_armor_policies", "projects/acme-prod/global/securityPolicies/edge-waf"),
)


@pytest.fixture(autouse=True)
def registered():
    """Registration is import-time and therefore PROCESS-GLOBAL: a sibling test
    that emptied the registry cannot get these back by re-importing an
    already-imported module, so this module's answer would otherwise depend on
    collection order."""
    mapping.reset_cache()
    map_network.register_all()
    yield
    mapping.reset_cache()


@pytest.fixture(scope="module")
def estate():
    return json.loads(ESTATE.read_text(encoding="utf-8"))


# -- driving the committed tfstate --------------------------------------------


def _state_objects(*types):
    """The committed tfstate as :class:`facts.TfObject` values.

    NOT the tfstate reader. The two rules it does obey are the two that would
    otherwise silently corrupt the pin: a DEPOSED generation is a leftover from
    a create-before-destroy and not current state, and an instance's index key
    belongs in its address so two instances of one resource are two objects.
    """
    doc = json.loads(STATE.read_text(encoding="utf-8"))
    out = []
    for entry in doc["resources"]:
        if entry.get("mode") != "managed":
            continue
        if types and entry["type"] not in types:
            continue
        for instance in entry["instances"]:
            if "deposed" in instance:
                continue
            index = instance.get("index_key")
            prefix = f"{entry['module']}." if entry.get("module") else ""
            suffix = "" if index is None else f"[{json.dumps(index)}]"
            out.append(facts.TfObject(
                address=f"{prefix}{entry['type']}.{entry['name']}{suffix}",
                type=entry["type"], name=entry["name"],
                module=entry.get("module") or "", index_key=index,
                source="tfstate", side="current", values=instance["attributes"],
                artifact=str(STATE)))
    return out


# -- driving the committed HCL corpus -----------------------------------------
#
# NOT an HCL reader either (that is tfsource/hcl.py's task). Top-level literal
# attributes are pulled out of the fixture; a NESTED block is spelled here and
# PINNED with an assertion against the fixture text on the line above it, so a
# fixture edit fails this file instead of quietly agreeing with a stale copy.

_NOTHING = object()


def _block(text, resource_type, name):
    """The body of one ``resource "<type>" "<name>"`` block."""
    header = f'resource "{resource_type}" "{name}" {{'
    start = text.index(header) + len(header)
    depth = 1
    lines = []
    for line in text[start:].splitlines():
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            break
        lines.append(line)
    return "\n".join(lines)


def _literal(raw):
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw in ("true", "false"):
        return raw == "true"
    if raw.lstrip("-").isdigit():
        return int(raw)
    if raw.startswith("[") and raw.endswith("]"):
        items = [item.strip() for item in raw[1:-1].split(",") if item.strip()]
        if items and all(len(item) >= 2 and item.startswith('"') and item.endswith('"')
                         for item in items):
            return [item[1:-1] for item in items]
    return _NOTHING


def _literals(block):
    """The block's own top-level literal attributes; nested blocks are skipped."""
    values = {}
    depth = 0
    for line in block.splitlines():
        stripped = line.strip()
        if depth == 0 and "=" in stripped and not stripped.startswith(("#", "//", "*")):
            key, _, raw = stripped.partition("=")
            parsed = _literal(raw.strip())
            if parsed is not _NOTHING:
                values[key.strip()] = parsed
        depth += stripped.count("{") - stripped.count("}")
    return values


def _hcl(resource_type, name, **nested):
    """One resource from main.tf as a :class:`facts.TfObject`, with ``nested``
    supplying the repeated blocks in the plan-JSON encoding."""
    block = _block(MAIN_TF.read_text(encoding="utf-8"), resource_type, name)
    values = dict(_literals(block))
    values.update(nested)
    return block, facts.TfObject(
        address=f"{resource_type}.{name}", type=resource_type, name=name,
        source="hcl-current", side="current", values=values, artifact=str(MAIN_TF))


def _object(resource_type, name, values, **overrides):
    """A synthetic object, for the degenerate shapes no committed fixture has."""
    return facts.TfObject(address=f"{resource_type}.{name}", type=resource_type,
                          name=name, source=overrides.pop("source", "tfstate"),
                          side=overrides.pop("side", "current"), values=values,
                          **overrides)


# -- assembling fragments -----------------------------------------------------


def _assemble(produced, category, key):
    """What ``tfsource/merge.py`` does with the fragments this mapper emits.

    Assembling here rather than importing it is deliberate: the merge engine is
    a LATER task, and the pin this test exists for — that a policy split across
    resources reassembles into the estate's own record — has to hold before it
    lands. The one rule reproduced is merge's ordering, PRIORITY then ADDRESS,
    because Cloud Armor and firewall-policy rule order is semantic and a rule in
    the wrong place is a different policy that still looks complete.
    """
    rows = [fact for fact in produced
            if fact.category == category and fact.key == key]
    assert rows, f"nothing was mapped for {category} {key}"
    assembled, rules, attachments = {}, [], []
    for fact in rows:
        for field, value in (fact.record or {}).items():
            if field == "rules":
                rules.extend((rule["priority"], fact.address, rule) for rule in value)
            elif field == "attachments":
                attachments.extend(value)
            else:
                assembled[field] = value
    spoken = {field for fact in rows for field in (fact.record or {})}
    if "rules" in spoken:
        assembled["rules"] = [rule for _priority, _address, rule
                              in sorted(rules, key=lambda row: row[:2])]
    if "attachments" in spoken:
        assembled["attachments"] = attachments
    return assembled


@pytest.fixture(scope="module")
def captured():
    """Every fact the committed tfstate produces, mapped once."""
    mapping.reset_cache()
    map_network.register_all()
    try:
        yield mapping.map_objects(_state_objects(), CTX)
    finally:
        mapping.reset_cache()


# -- THE HEADLINE PIN ---------------------------------------------------------


@pytest.mark.parametrize("category,key", HEADLINE)
def test_the_headline_records_equal_the_loaded_estate_fixture(captured, estate,
                                                              category, key):
    assert _assemble(captured.facts, category, key) == estate[category][key]


def test_the_committed_corpus_maps_without_a_single_failure(captured):
    """A crash-isolated mapper failure would leave the pin above passing on the
    records that happened not to crash."""
    assert captured.failures == ()
    assert captured.skipped == ()


def test_every_emitted_record_validates_through_the_estate_tables_constructor(
        captured, estate):
    """The estate's own strict constructor is the schema; a record that only
    this test agrees with is a record no snapshot could ever hold."""
    tables = {}
    for category, _key in HEADLINE:
        keys = {fact.key for fact in captured.facts if fact.category == category}
        tables[category] = {key: _assemble(captured.facts, category, key)
                            for key in sorted(keys)}

    snapshot = knowledge.GcpSnapshot.from_dict(
        {"captured_at": estate["captured_at"], **tables})

    # and it survives the table's own round trip, which is what a captured
    # snapshot on disk actually goes through
    emitted = snapshot.to_dict()
    for category, key in HEADLINE:
        assert emitted[category][key] == estate[category][key]


# -- the TypeSet order --------------------------------------------------------


def _health_check_allow_blocks():
    """``allow-health-checks``' two committed allow blocks, pinned against
    main.tf: the provider spells each protocol/ports pair as its own TypeSet
    block, and a TypeSet's array order is hash-determined."""
    block = _block(MAIN_TF.read_text(encoding="utf-8"),
                   "google_compute_firewall", "allow_health_checks")
    assert block.count("allow {") == 2, "the two-block fixture lost a block"
    assert 'ports    = ["80"]' in block and 'ports    = ["443"]' in block
    return [{"protocol": "tcp", "ports": ["80"]},
            {"protocol": "tcp", "ports": ["443"]}]


def test_two_allow_blocks_in_either_array_order_produce_one_record():
    blocks = _health_check_allow_blocks()
    _text, forward = _hcl("google_compute_firewall", "allow_health_checks",
                          allow=list(blocks))
    _text, reversed_ = _hcl("google_compute_firewall", "allow_health_checks",
                            allow=list(reversed(blocks)))

    one = map_network.map_firewall(forward, CTX)[0]
    other = map_network.map_firewall(reversed_, CTX)[0]

    assert json.dumps(one.record, sort_keys=True) == json.dumps(other.record,
                                                                sort_keys=True)
    # and BOTH blocks survived: taking the first would shrink the rule silently
    assert [entry["ports"] for entry in one.record["layer4"]] == [["443"], ["80"]]


def test_the_eight_typesets_are_the_attributes_that_sort():
    """The stated list and the attributes :func:`map_firewall` actually orders
    are one list, so neither can drift away from the other."""
    assert map_network.FIREWALL_TYPESETS == (
        "allow", "deny", "source_ranges", "destination_ranges", "source_tags",
        "target_tags", "source_service_accounts", "target_service_accounts")


def test_a_range_list_is_ordered_by_the_address_it_starts_at(captured, estate):
    """The one committed multi-member range list. Sorted as TEXT it would come
    out the other way round, which is not the order the estate stores."""
    key = f"{FIREWALL}allow-health-checks"
    stored = estate["firewall_rules"][key]["source_ranges"]
    assert stored == ["35.191.0.0/16", "130.211.0.0/22"]
    assert sorted(stored) != stored, "this fixture no longer pins the order rule"
    assert _assemble(captured.facts, "firewall_rules", key)["source_ranges"] == stored


def test_an_upper_case_protocol_is_folded():
    """Driven from main.tf, which spells ``TCP`` on purpose."""
    block, obj = _hcl("google_compute_firewall", "allow_internal",
                      allow=[{"protocol": "TCP", "ports": ["0-65535"]}])
    assert 'protocol = "TCP"' in block

    record = map_network.map_firewall(obj, CTX)[0].record

    assert record["layer4"] == [{"protocol": "tcp", "ports": ["0-65535"]}]


# -- BOTH-OR-NEITHER ----------------------------------------------------------


_FIREWALL_BASE = {"name": "both-ways", "project": "acme-prod",
                  "network": "projects/acme-prod/global/networks/vpc-main",
                  "direction": "INGRESS"}


def test_a_firewall_carrying_both_an_allow_and_a_deny_has_no_action():
    obj = _object("google_compute_firewall", "both_ways",
                  {**_FIREWALL_BASE,
                   "allow": [{"protocol": "tcp", "ports": ["80"]}],
                   "deny": [{"protocol": "tcp", "ports": ["22"]}]})

    fact = map_network.map_firewall(obj, CTX)[0]

    assert facts.is_unresolved(fact.record["action"])
    assert fact.record["action"].reason == "ambiguous_key"
    assert fact.record["action"] in fact.unresolved
    # the reach is undecided too: merging the two blocks would describe one rule
    # that both permits and blocks
    assert facts.is_unresolved(fact.record["layer4"])


def test_a_firewall_carrying_neither_has_no_action_either():
    obj = _object("google_compute_firewall", "neither", dict(_FIREWALL_BASE))

    fact = map_network.map_firewall(obj, CTX)[0]

    assert facts.is_unresolved(fact.record["action"])
    assert fact.record["layer4"] == []


def test_both_block_lists_present_and_both_empty_is_the_neither_case():
    """A plan spells every attribute, so both keys are present with no block in
    either; that says exactly as little as writing neither key does."""
    obj = _object("google_compute_firewall", "empty_both",
                  {**_FIREWALL_BASE, "allow": [], "deny": []})

    fact = map_network.map_firewall(obj, CTX)[0]

    assert facts.is_unresolved(fact.record["action"])
    assert "carries neither" in fact.record["action"].detail
    assert fact.record["layer4"] == []


def test_an_empty_allow_block_list_is_still_an_allow(captured, estate):
    """``allow-health-checks`` is captured with ``allow = []`` and no ``deny``
    key at all. PRESENCE decides: an allow that permits nothing is a rule this
    mapper reports, not one whose action it may guess."""
    key = f"{FIREWALL}allow-health-checks"
    record = _assemble(captured.facts, "firewall_rules", key)
    assert record["action"] == "allow" and record["layer4"] == []
    assert record["action"] == estate["firewall_rules"][key]["action"]


# -- THE FOURTH ACTION --------------------------------------------------------


def test_an_unrecognised_policy_action_is_unresolved_and_never_goto_next():
    obj = _object("google_compute_firewall_policy_rule", "profiled",
                  {"firewall_policy": "fp-baseline", "priority": 500,
                   "action": "apply_security_profile_group", "direction": "INGRESS",
                   "match": [{"src_ip_ranges": ["0.0.0.0/0"]}]})

    result = mapping.map_objects([obj], CTX)

    assert len(result.facts) == 1
    action = result.facts[0].record["rules"][0]["action"]
    assert facts.is_unresolved(action) and action.reason == "unparsed"
    assert "goto_next" not in repr(result), (
        "coercing an unmodelled action into the pass-through action would turn "
        "a filtering rule into one that filters nothing")
    assert "goto_next" not in "".join(
        marker.detail for marker in result.facts[0].unresolved)


def test_a_recognised_policy_action_still_comes_through(captured):
    """The refusal above is about actions this mapper does not model, not about
    the pass-through action itself, which the committed corpus does carry."""
    assembled = _assemble(captured.facts, "hierarchical_firewall_policies",
                          "organizations/1/locations/global/firewallPolicies/fp-baseline")

    assert [rule["action"] for rule in assembled["rules"]] == ["deny", "goto_next"]


# -- fragments ----------------------------------------------------------------


def test_a_policy_rule_with_no_parent_policy_still_emits_its_fragment():
    """The mapper does not hand-join fragments, so it cannot need the parent to
    be in the same artifact: a fragment that only existed when its parent did
    would vanish from every split configuration."""
    objects = _state_objects("google_compute_firewall_policy_rule")
    assert objects and all(obj.type == "google_compute_firewall_policy_rule"
                           for obj in objects)

    result = mapping.map_objects(objects, CTX)

    assert len(result.facts) == len(objects)
    assert {fact.key for fact in result.facts} == {
        "organizations/1/locations/global/firewallPolicies/fp-baseline"}
    assert {fact.fragment for fact in result.facts} == {"rules"}


def test_the_association_speaks_only_for_the_attachments():
    objects = _state_objects("google_compute_firewall_policy_association")
    result = mapping.map_objects(objects, CTX)

    assert [fact.fragment for fact in result.facts] == ["attachments"]
    assert result.facts[0].record == {"attachments": ["organizations/1"]}


# -- THE CLOUD ARMOR ASSEMBLY PIN ---------------------------------------------


ARMOR = "projects/acme-prod/global/securityPolicies/edge-waf"


def _assert_edge_waf(produced, estate):
    assembled = _assemble(produced, "cloud_armor_policies", ARMOR)
    assert assembled == estate["cloud_armor_policies"][ARMOR]
    assert [rule["priority"] for rule in assembled["rules"]] == [1000, 2147483647]


def test_the_standalone_armor_rule_assembles_from_the_tfstate(estate):
    objects = _state_objects("google_compute_security_policy",
                             "google_compute_security_policy_rule")
    assert len(objects) == 2, "the split-policy fixture lost one of its halves"

    _assert_edge_waf(mapping.map_objects(objects, CTX).facts, estate)


def test_the_standalone_armor_rule_assembles_from_the_hcl_corpus(estate):
    text = MAIN_TF.read_text(encoding="utf-8")
    inline = _block(text, "google_compute_security_policy", "edge_waf")
    assert 'action      = "deny(403)"' in inline and "priority    = 1000" in inline
    assert 'versioned_expr = "SRC_IPS_V1"' in inline
    assert 'src_ip_ranges = ["203.0.113.0/24"]' in inline
    standalone = _block(text, "google_compute_security_policy_rule", "edge_waf_default")
    assert 'src_ip_ranges = ["*"]' in standalone

    _policy_text, policy = _hcl(
        "google_compute_security_policy", "edge_waf",
        rule=[{"action": "deny(403)", "priority": 1000, "preview": False,
               "description": 'Block the "noisy scanner" range',
               "match": [{"versioned_expr": "SRC_IPS_V1",
                          "config": [{"src_ip_ranges": ["203.0.113.0/24"]}]}]}])
    _rule_text, rule = _hcl(
        "google_compute_security_policy_rule", "edge_waf_default",
        match=[{"versioned_expr": "SRC_IPS_V1",
                "config": [{"src_ip_ranges": ["*"]}]}])

    _assert_edge_waf(mapping.map_objects([policy, rule], CTX).facts, estate)


def test_the_inline_half_alone_is_a_policy_that_only_denies(estate):
    """Why the standalone rule is not optional: without it the same artifact
    captures as a policy whose last word is a deny."""
    objects = _state_objects("google_compute_security_policy")

    assembled = _assemble(mapping.map_objects(objects, CTX).facts,
                          "cloud_armor_policies", ARMOR)

    assert [rule["action"] for rule in assembled["rules"]] == ["deny(403)"]
    assert assembled != estate["cloud_armor_policies"][ARMOR]


# -- THE BARE-NETWORK RULE ----------------------------------------------------


def test_a_bare_network_expands_when_the_project_is_a_literal():
    obj = _object("google_compute_firewall", "bare_net",
                  {"name": "bare-net", "project": "acme-prod", "network": "default",
                   "direction": "INGRESS",
                   "allow": [{"protocol": "tcp", "ports": ["22"]}]})

    fact = map_network.map_firewall(obj, CTX)[0]

    assert fact.record["network"] == "projects/acme-prod/global/networks/default"
    assert fact.unresolved == ()


def test_a_bare_network_without_a_project_keeps_the_raw_value_and_flags_it():
    obj = _object("google_compute_firewall", "bare_net",
                  {"name": "projects/acme-prod/global/firewalls/bare-net",
                   "network": "default", "direction": "INGRESS",
                   "allow": [{"protocol": "tcp", "ports": ["22"]}]})

    fact = map_network.map_firewall(obj, mapping.MapContext())

    assert fact[0].record["network"] == "default", "never guess a project"
    markers = [marker for marker in fact[0].unresolved
               if marker.reason == "missing_project"]
    assert [marker.path for marker in markers] == [
        "google_compute_firewall.bare_net.network"]


# -- the side facts -----------------------------------------------------------


def test_network_tags_and_service_accounts_are_emitted_per_member():
    obj = _object("google_compute_firewall", "tagged",
                  {**_FIREWALL_BASE, "name": "tagged",
                   "allow": [{"protocol": "tcp", "ports": ["80"]}],
                   "source_tags": ["bastion", "db"], "target_tags": ["web"],
                   "source_service_accounts":
                       ["ci-deployer@acme-prod.iam.gserviceaccount.com"],
                   "target_service_accounts":
                       ["serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com"]})

    produced = map_network.map_firewall(obj, CTX)

    assert [fact.key for fact in produced if fact.category == "network_tags"] == [
        "bastion", "db", "web"]
    assert [fact.key for fact in produced if fact.category == "service_accounts"] == [
        "ci-deployer@acme-prod.iam.gserviceaccount.com",
        "etl-runner@acme-prod.iam.gserviceaccount.com"]
    # a flat category carries a name and no record
    assert all(fact.record is None for fact in produced[1:])


def test_a_tag_list_that_could_not_be_read_contributes_no_names():
    obj = _object("google_compute_firewall", "interpolated",
                  {**_FIREWALL_BASE, "name": "interpolated",
                   "allow": [{"protocol": "tcp", "ports": ["80"]}],
                   "source_tags": ["web", "${var.tier}"]})

    produced = map_network.map_firewall(obj, CTX)

    assert [fact.category for fact in produced] == ["firewall_rules"]
    assert facts.is_unresolved(produced[0].record["source_tags"])


# -- the registry seam --------------------------------------------------------


def test_the_module_claims_exactly_the_six_network_types():
    claimed = {resource_type: entry.category
               for resource_type, entry in mapping.mappers().items()
               if entry.module == map_network.__name__}

    assert claimed == {
        "google_compute_firewall": "firewall_rules",
        "google_compute_firewall_policy": "hierarchical_firewall_policies",
        "google_compute_firewall_policy_rule": "hierarchical_firewall_policies",
        "google_compute_firewall_policy_association": "hierarchical_firewall_policies",
        "google_compute_security_policy": "cloud_armor_policies",
        "google_compute_security_policy_rule": "cloud_armor_policies",
    }


def test_every_stated_gap_carries_its_reason_and_is_in_the_one_consulted_list():
    assert map_network.DELIBERATELY_UNMAPPED
    for resource_type, reason in map_network.DELIBERATELY_UNMAPPED.items():
        assert resource_type.startswith("google_") and len(reason) > 40
        assert mapping.DELIBERATELY_UNMAPPED[resource_type] == reason
        assert resource_type not in mapping.mappers()

    stated = sorted(map_network.DELIBERATELY_UNMAPPED)[0]
    result = mapping.map_objects(
        [_object(stated, "thing", {})], CTX)

    assert [row.reason for row in result.unmapped] == ["deliberate"]
    assert result.notes == (), "a stated gap is not an oversight the census counts"


def test_canonical_from_object_answers_with_the_estate_key(estate):
    """The translation the PROPOSED side uses is the same one the capture side
    does, so a proposal and a capture cannot spell one rule two ways."""
    obj = next(o for o in _state_objects("google_compute_firewall")
               if o.values["name"] == "allow-iap-ssh")

    category, key, record = mapping.canonical_from_object(obj, CTX)

    assert category == "firewall_rules"
    assert key == f"{FIREWALL}allow-iap-ssh"
    assert record == estate["firewall_rules"][key]
