"""The effective org-policy fold (F3): merge table, abstentions, collections.

``gcp_grounding/org_effective.py`` folds ``snapshot.org_policies`` +
``snapshot.resource_hierarchy`` + the proposal's own set-policy into the two
estate-tier collections ``effective_org_policy_bool`` /
``effective_org_policy_values`` and the ``org_effective`` document check.
This module pins:

* the MERGE TABLE, one test per documented decidable case (D1-D12 and the
  overlay's MERGE-O1), driven through the pure engine functions and through
  the registered extractors;
* EVERY named abstention (A2-A25 of the design's index), each asserting that
  the refusal fires AND names its cause — conditions, uncaptured categories,
  chain damage, oneof violations, type confusion, unknown defaults, unknown
  nodes, duplicate targets, unknown multiplicity;
* the compiled-promise path end to end (the design's two example promises),
  the SUBJECTS set-generalization (a constraint-scoped promise over a
  document about a DIFFERENT constraint abstains by name, on both the REST
  and the terraform kind), the witness address threading, the per-collection
  type-split abstention, and the evidence floor;
* the document check's inert and blast-radius findings, and that an
  undecidable fold is one ``unverified`` on the record, never a silent skip;
* the additive ``constraint_default`` capture (fetch + knowledge validation).

NAMED MUTATION MUST-KILLS PINNED HERE: MK-F01..MK-F14 (see
tests/mutation_entries.py's ORG_EFFECTIVE_ENTRIES block — the id family is
MK-F, NOT the design's MK-E, because MK-E01..07 are already reserved for
gx-iam-escalation-evidence in the register's required-id tuple). Each entry
was MEASURED against a working-tree copy before being seeded, per the
register's doctrine minus the git-archive materialisation an uncommitted tree
cannot satisfy — the same recorded substitution the deny pair made.

HAVE_Z3-branched exactly as tests/test_gcp_deny_domains.py: the promise cases
assert the documented builtin abstention when z3 is absent and the real
grounded/contradicted buckets when it is present; the extractors themselves
are solver-free and asserted unbranched.
"""

from __future__ import annotations

from unittest import mock

import pytest

from gcp_grounding import (evidence, org_effective, sec_artifact, sec_ast,
                           sec_domains, sec_encode, sec_probes, sec_rules)
from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.solver import get_solver
from gcp_grounding.fetch import fetch_constraints
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.registry import CheckContext
from gcp_grounding.sec_domains import _Undecidable

_SOLVER = get_solver()
Z3 = _z3_module(_SOLVER)
HAVE_Z3 = _SOLVER.backend == "z3"

ORG = "organizations/1"
FOLDER = "folders/2"
P1 = "projects/p1"
P2 = "projects/p2"

BOOL_NODEF = "bool.noDefault"
BOOL_DENY = "bool.defaultDeny"
BOOL_ALLOW = "bool.defaultAllow"
LIST_NODEF = "list.noDefault"
LIST_ALLOW = "list.defaultAllow"
LIST_DENY = "list.defaultDeny"


# =============================================================================
# world builders
# =============================================================================


def hierarchy() -> dict:
    return {
        ORG: {"parent": None, "type": "organization"},
        FOLDER: {"parent": ORG, "type": "folder"},
        P1: {"parent": FOLDER, "type": "project", "number": "111"},
        P2: {"parent": FOLDER, "type": "project", "number": "222"},
    }


def constraints() -> dict:
    return {
        f"constraints/{BOOL_NODEF}": {"value_type": "boolean"},
        f"constraints/{BOOL_DENY}": {"value_type": "boolean",
                                     "constraint_default": "DENY"},
        f"constraints/{BOOL_ALLOW}": {"value_type": "boolean",
                                      "constraint_default": "ALLOW"},
        f"constraints/{LIST_NODEF}": {"value_type": "list"},
        f"constraints/{LIST_ALLOW}": {"value_type": "list",
                                      "constraint_default": "ALLOW"},
        f"constraints/{LIST_DENY}": {"value_type": "list",
                                     "constraint_default": "DENY"},
        "constraints/odd.unknownType": {"value_type": "unknown"},
    }


def rule(*, enforce=None, allowed=(), denied=(), allow_all=None,
         deny_all=None, condition=None) -> dict:
    return {"enforce": enforce, "allow_all": allow_all, "deny_all": deny_all,
            "allowed_values": list(allowed), "denied_values": list(denied),
            "condition": condition}


def set_policy(node: str, constraint: str, *rules, reset=False,
               inherit=False) -> tuple[str, dict]:
    full = f"constraints/{constraint}"
    return (f"{node}|{full}", {"node": node, "constraint": full,
                               "reset": reset, "inherit_from_parent": inherit,
                               "rules": list(rules)})


def snapshot(*policies, drop=(), extra_constraints=None,
             tree=None) -> GcpSnapshot:
    data: dict = {
        "captured_at": "2026-07-18T09:00:00Z",
        "constraints": {**constraints(), **(extra_constraints or {})},
        "resource_hierarchy": tree if tree is not None else hierarchy(),
        "org_policies": dict(policies),
    }
    for category in drop:
        data.pop(category, None)
    return GcpSnapshot.from_dict(data)


def rest_doc(constraint: str, node: str = P1, *, rules=None, reset=None,
             inherit=None) -> dict:
    spec: dict = {}
    if rules is not None:
        spec["rules"] = rules
    if reset is not None:
        spec["reset"] = reset
    if inherit is not None:
        spec["inheritFromParent"] = inherit
    return {"name": f"{node}/policies/{constraint}", "spec": spec}


def tf_resource(address_leaf: str, constraint: str, node: str = P1, *,
                rules=None, reset=None, inherit=None, parent=None,
                name=None, extra_values=None) -> dict:
    spec: dict = {"reset": reset, "inherit_from_parent": inherit,
                  "rules": rules if rules is not None else []}
    values: dict = {
        "name": (name if name is not None
                 else f"{node}/policies/{constraint}"),
        "spec": [spec],
    }
    if parent is not None:
        values["parent"] = parent
    if extra_values:
        values.update(extra_values)
    return {
        "address": f"google_org_policy_policy.{address_leaf}",
        "mode": "managed",
        "type": "google_org_policy_policy",
        "name": address_leaf,
        "provider_name": "registry.terraform.io/hashicorp/google",
        "values": values,
    }


def tf_rule(*, enforce=None, allowed=None, denied=None, allow_all=None,
            deny_all=None, condition=None) -> dict:
    values: list = []
    if allowed is not None or denied is not None:
        block: dict = {}
        if allowed is not None:
            block["allowed_values"] = list(allowed)
        if denied is not None:
            block["denied_values"] = list(denied)
        values = [block]
    return {"enforce": enforce, "allow_all": allow_all, "deny_all": deny_all,
            "values": values, "condition": condition if condition else []}


def plan(*resources) -> dict:
    return {"format_version": "1.2",
            "planned_values": {"root_module": {"resources": list(resources)}}}


@pytest.fixture(autouse=True)
def _isolate():
    """Restore both registries and the registration guard around every test."""
    saved_collections = dict(sec_ast.COLLECTIONS)
    saved_extractors = dict(sec_rules.EXTRACTORS)
    sec_domains.reset()
    sec_domains.register()
    yield
    sec_rules.RULES.clear()
    sec_rules._LAST_WITNESS.clear()
    sec_ast.COLLECTIONS.clear()
    sec_ast.COLLECTIONS.update(saved_collections)
    sec_rules.EXTRACTORS.clear()
    sec_rules.EXTRACTORS.update(saved_extractors)
    sec_domains.reset()
    sec_domains.register()


def ctx(document, kind, snap):
    return sec_rules.RuleContext(snapshot=snap, document=document,
                                 document_kind=kind)


def extract(collection, context):
    """→ (records, missing_reason, empty_because), through the floor."""
    result = sec_rules.EXTRACTORS[collection](context)
    return sec_rules._normalize_extraction(collection, result)


def bool_rows(document, snap, kind="org_policy"):
    return extract("effective_org_policy_bool", ctx(document, kind, snap))


def values_rows(document, snap, kind="org_policy"):
    return extract("effective_org_policy_values", ctx(document, kind, snap))


# -- pure-engine harness -------------------------------------------------------


def norm_policy(*rules, reset=False, inherit=False) -> dict:
    return {"reset": reset, "inherit_from_parent": inherit,
            "rules": tuple(
                org_effective._normalized_rule(r, "test rule")
                for r in rules)}


def pol_from(table: dict):
    return lambda node: table.get(node)


CHAIN_P1 = (ORG, FOLDER, P1)
CHAIN_FOLDER = (ORG, FOLDER)

BOOL_REC_NODEF = {"value_type": "boolean"}
BOOL_REC_DENY = {"value_type": "boolean", "constraint_default": "DENY"}
BOOL_REC_ALLOW = {"value_type": "boolean", "constraint_default": "ALLOW"}
LIST_REC_ALLOW = {"value_type": "list", "constraint_default": "ALLOW"}
LIST_REC_DENY = {"value_type": "list", "constraint_default": "DENY"}
LIST_REC_NODEF = {"value_type": "list"}


# =============================================================================
# the merge table — boolean arm (D1, D2, D3; A14-A22)
# =============================================================================


def test_bool_nearest_set_wins():
    """D1 (MK-F01): the LOWEST node on the chain with a policy stating
    ``enforce`` decides — an org-level true never overrides the project's own
    false."""
    pol = pol_from({ORG: norm_policy(rule(enforce=True)),
                    P1: norm_policy(rule(enforce=False))})
    assert org_effective._effective_bool(CHAIN_P1, pol, BOOL_NODEF,
                                         BOOL_REC_NODEF) is False
    assert org_effective._effective_bool(CHAIN_FOLDER, pol, BOOL_NODEF,
                                         BOOL_REC_NODEF) is True


def test_bool_default_deny_is_enforced():
    """D2 (MK-F03): no policy anywhere on the chain — the captured managed
    default decides: DENY is enforced-by-default, ALLOW is not."""
    pol = pol_from({})
    assert org_effective._effective_bool(CHAIN_P1, pol, BOOL_DENY,
                                         BOOL_REC_DENY) is True
    assert org_effective._effective_bool(CHAIN_P1, pol, BOOL_ALLOW,
                                         BOOL_REC_ALLOW) is False


def test_bool_reset_restores_default():
    """D3 (MK-F02): a reset at the project clears the org's enforce and
    restores the managed default — it never lets the ancestor leak through."""
    pol = pol_from({ORG: norm_policy(rule(enforce=True)),
                    P1: norm_policy(reset=True)})
    assert org_effective._effective_bool(CHAIN_P1, pol, BOOL_ALLOW,
                                         BOOL_REC_ALLOW) is False


def test_bool_default_unknown_abstains_by_name():
    """A20: a fold that bottoms out at the managed default with no captured
    ``constraint_default`` abstains naming the field, never guesses."""
    with pytest.raises(_Undecidable) as exc:
        org_effective._effective_bool(CHAIN_P1, pol_from({}), BOOL_NODEF,
                                      BOOL_REC_NODEF)
    assert "constraint_default" in str(exc.value)
    assert BOOL_NODEF in str(exc.value)


def test_bool_inherit_from_parent_abstains():
    """A22: inheritFromParent is not meaningful for boolean constraints."""
    pol = pol_from({P1: norm_policy(rule(enforce=True), inherit=True)})
    with pytest.raises(_Undecidable) as exc:
        org_effective._effective_bool(CHAIN_P1, pol, BOOL_NODEF,
                                      BOOL_REC_NODEF)
    assert "inheritFromParent" in str(exc.value) and P1 in str(exc.value)


def test_bool_contradictory_enforce_abstains():
    """A18: enforce true AND false within one policy is contradictory."""
    pol = pol_from({P1: norm_policy(rule(enforce=True), rule(enforce=False))})
    with pytest.raises(_Undecidable) as exc:
        org_effective._effective_bool(CHAIN_P1, pol, BOOL_NODEF,
                                      BOOL_REC_NODEF)
    assert "enforce=true AND enforce=false" in str(exc.value)


def test_condition_on_chain_abstains_by_name():
    """A14 (MK-F08): a conditional rule anywhere on the folded chain abstains
    naming the node AND the rule index — request-time facts are never
    decided offline."""
    # nearest-first: P1 decides BEFORE the org is read, so put the condition
    # on the deciding node itself to prove the gate runs where it decides.
    pol_deciding = pol_from({P1: norm_policy(
        rule(enforce=False, condition="resource.matchTag(...)"))})
    with pytest.raises(_Undecidable) as exc:
        org_effective._effective_bool(CHAIN_P1, pol_deciding, BOOL_NODEF,
                                      BOOL_REC_NODEF)
    assert "condition" in str(exc.value)
    assert P1 in str(exc.value) and "rules[0]" in str(exc.value)


def test_ambiguous_rule_abstains():
    """A16 (MK-F10): a rule stating more than one of the oneof value keys
    abstains — which one decides is a guess the fold refuses."""
    pol = pol_from({P1: norm_policy(rule(enforce=True, allow_all=True))})
    with pytest.raises(_Undecidable) as exc:
        org_effective._effective_bool(CHAIN_P1, pol, BOOL_NODEF,
                                      BOOL_REC_NODEF)
    assert "more than one of the oneof" in str(exc.value)


def test_a_rule_stating_nothing_abstains():
    """A16, the empty half: a rule stating none of the value keys decides
    nothing."""
    pol = pol_from({P1: norm_policy(rule())})
    with pytest.raises(_Undecidable) as exc:
        org_effective._effective_bool(CHAIN_P1, pol, BOOL_NODEF,
                                      BOOL_REC_NODEF)
    assert "states nothing decidable" in str(exc.value)


def test_a_policy_recording_nothing_abstains():
    """A19: empty rules with neither reset nor inheritFromParent records
    nothing — and a record that records nothing decides nothing."""
    pol = pol_from({P1: norm_policy()})
    with pytest.raises(_Undecidable) as exc:
        org_effective._effective_bool(CHAIN_P1, pol, BOOL_NODEF,
                                      BOOL_REC_NODEF)
    assert "records nothing" in str(exc.value)


def test_reset_with_rules_is_malformed():
    """A15: reset=true carrying rules of its own is malformed, in both arms."""
    pol = pol_from({P1: norm_policy(rule(enforce=True), reset=True)})
    with pytest.raises(_Undecidable) as exc:
        org_effective._effective_bool(CHAIN_P1, pol, BOOL_NODEF,
                                      BOOL_REC_NODEF)
    assert "reset=true AND carries" in str(exc.value)


def test_type_confusion_abstains_both_directions():
    """A17: a list-shaped rule under a boolean constraint, and a boolean-shaped
    rule under a list constraint, abstain naming the node — never coerced."""
    listish = pol_from({P1: norm_policy(rule(allowed=("v",)))})
    with pytest.raises(_Undecidable) as exc:
        org_effective._effective_bool(CHAIN_P1, listish, BOOL_NODEF,
                                      BOOL_REC_NODEF)
    assert "list-shaped" in str(exc.value) and P1 in str(exc.value)

    boolish = pol_from({P1: norm_policy(rule(enforce=True))})
    with pytest.raises(_Undecidable) as exc:
        org_effective._effective_list(CHAIN_P1, boolish, LIST_ALLOW,
                                      LIST_REC_ALLOW)
    assert "boolean-shaped" in str(exc.value) and P1 in str(exc.value)


# =============================================================================
# the merge table — list arm (D4-D10, A21)
# =============================================================================


def list_state(chain, pol, constraint=LIST_NODEF, record=LIST_REC_NODEF):
    return org_effective._effective_list(chain, pol, constraint, record)


def test_list_replace_drops_parent_values():
    """D4 (MK-F05): inheritFromParent=false REPLACES the parent's effective
    policy — the org's allowlist is gone, not merged."""
    pol = pol_from({ORG: norm_policy(rule(allowed=("a",))),
                    P1: norm_policy(rule(allowed=("b",)))})
    state = list_state(CHAIN_P1, pol)
    assert state["allowed"] == {"b"}
    assert "a" not in state["allowed"]


def test_list_inherit_merges_parent_values():
    """D5 (MK-F04): inheritFromParent=true MERGES this node's rules into the
    parent's effective policy — union of both sides across two levels."""
    pol = pol_from({ORG: norm_policy(rule(allowed=("a",), denied=("x",))),
                    FOLDER: norm_policy(rule(allowed=("b",)), inherit=True),
                    P1: norm_policy(rule(denied=("y",)), inherit=True)})
    state = list_state(CHAIN_P1, pol)
    assert state["allowed"] == {"a", "b"}
    assert state["denied"] == {"x", "y"}


def test_list_inherit_at_top_merges_with_the_captured_default():
    """D6: an inherit policy at the top of the chain merges with the managed
    default — decidable only because the default is captured."""
    pol = pol_from({P1: norm_policy(rule(denied=("v",)), inherit=True)})
    state = list_state(CHAIN_P1, pol, LIST_ALLOW, LIST_REC_ALLOW)
    assert state["allow_all"] is True and state["denied"] == {"v"}


def test_list_reset_midchain_then_lower_policy():
    """D10: a reset mid-chain clears the org's denials; the project then
    builds on the default alone."""
    pol = pol_from({ORG: norm_policy(rule(denied=("x",))),
                    FOLDER: norm_policy(reset=True),
                    P1: norm_policy(rule(allowed=("y",)))})
    state = list_state(CHAIN_P1, pol)
    assert state["allowed"] == {"y"} and state["denied"] == set()
    # at the folder itself the reset bottoms out at the default (A20 without
    # a captured one; decidable with one)
    with pytest.raises(_Undecidable):
        list_state(CHAIN_FOLDER, pol)
    assert list_state(CHAIN_FOLDER, pol, LIST_ALLOW,
                      LIST_REC_ALLOW)["allow_all"] is True


def test_deny_precedence_suppresses_allow_row():
    """D7 (MK-F06): a value on BOTH sides emits only its deny row — an allow
    row for an effectively denied value would fabricate a refutation."""
    rows = org_effective._list_rows(
        {"allowed": {"a", "b"}, "denied": {"b"},
         "allow_all": False, "deny_all": False}, P1, LIST_NODEF, "")
    allows = [r["value"] for r in rows if r["polarity"] == "allow"]
    denies = [r["value"] for r in rows if r["polarity"] == "deny"]
    assert allows == ["a"] and denies == ["b"]


def test_deny_all_emits_no_allow_rows():
    """D8 (MK-F07): effective denyAll suppresses every allow row."""
    rows = org_effective._list_rows(
        {"allowed": {"a"}, "denied": set(),
         "allow_all": False, "deny_all": True}, P1, LIST_NODEF, "")
    assert rows == [{"node": P1, "constraint": LIST_NODEF,
                     "polarity": "deny", "value": "", "all_values": True}]


def test_allow_all_with_specific_denies():
    """D9: allowAll with enumerated denies means "all except the denied" —
    one allow all_values row beside the deny value rows."""
    rows = org_effective._list_rows(
        {"allowed": set(), "denied": {"v"},
         "allow_all": True, "deny_all": False}, P1, LIST_NODEF, "")
    assert {(r["polarity"], r["value"], r["all_values"]) for r in rows} == {
        ("deny", "v", False), ("allow", "", True)}


def test_effective_allow_all_and_deny_all_abstains():
    """A21: the two allValues flags effective at once is malformed."""
    with pytest.raises(_Undecidable) as exc:
        org_effective._list_rows(
            {"allowed": set(), "denied": set(),
             "allow_all": True, "deny_all": True}, P1, LIST_NODEF, "")
    assert "simultaneously" in str(exc.value)


# =============================================================================
# chain damage and the universe (A11, A12, MK-F11, MK-F12)
# =============================================================================


def test_dangling_parent_abstains():
    """A11 (MK-F11): a parent named but not captured is chain damage — the
    fold never silently shortens the chain."""
    tree = hierarchy()
    tree[P1] = {"parent": "folders/999", "type": "project", "number": "111"}
    with pytest.raises(_Undecidable) as exc:
        org_effective._chain(tree, P1)
    assert "folders/999" in str(exc.value)
    assert "broken" in str(exc.value)


def test_hierarchy_cycle_abstains():
    """A12: a cycle abstains naming a node on it."""
    tree = {ORG: {"parent": FOLDER, "type": "organization"},
            FOLDER: {"parent": ORG, "type": "folder"}}
    with pytest.raises(_Undecidable) as exc:
        org_effective._chain(tree, FOLDER)
    assert "cycle" in str(exc.value)


def test_descendants_in_universe():
    """MK-F12: the universe of a folder-level target is the folder AND every
    captured descendant — a folder change's project-level effect is judged."""
    assert org_effective._universe(hierarchy(), FOLDER) == (FOLDER, P1, P2)
    assert org_effective._universe(hierarchy(), P1) == (P1,)


# =============================================================================
# the extractors, end to end
# =============================================================================


def test_rest_overlay_replaces_captured_policy():
    """MERGE-O1 (MK-F09): the proposal's set-policy REPLACES the captured
    record at its (node, constraint) — it is never folded WITH it."""
    snap = snapshot(set_policy(P1, BOOL_NODEF, rule(enforce=True)))
    doc = rest_doc(BOOL_NODEF, P1, rules=[{"enforce": False}])
    records, missing, _ = bool_rows(doc, snap)
    assert missing is None
    assert records == ({"node": P1, "constraint": BOOL_NODEF,
                        "enforce": False},)


def test_folder_proposal_rows_cover_the_descendants():
    """D1 through the extractor: the folder overlay decides at the folder and
    at the descendant that has no policy of its own, while the project's own
    policy still wins at that project."""
    snap = snapshot(set_policy(P1, BOOL_NODEF, rule(enforce=False)))
    doc = rest_doc(BOOL_NODEF, FOLDER, rules=[{"enforce": True}])
    records, missing, _ = bool_rows(doc, snap)
    assert missing is None
    assert records == (
        {"node": FOLDER, "constraint": BOOL_NODEF, "enforce": True},
        {"node": P1, "constraint": BOOL_NODEF, "enforce": False},
        {"node": P2, "constraint": BOOL_NODEF, "enforce": True},
    )


def test_project_number_alias_resolves():
    """D12: a proposal naming ``projects/<number>`` folds at the captured
    project it aliases."""
    snap = snapshot()
    doc = rest_doc(BOOL_DENY, "projects/111", rules=[{"enforce": False}])
    records, missing, _ = bool_rows(doc, snap)
    assert missing is None
    assert records == ({"node": P1, "constraint": BOOL_DENY,
                        "enforce": False},)


def test_tf_rows_thread_the_block_address_and_rest_rows_do_not():
    snap = snapshot()
    doc = plan(tf_resource("no_ext_ip", LIST_DENY, P1,
                           rules=[tf_rule(allowed=("projects/p1/x",))]))
    records, missing, _ = values_rows(doc, snap, kind="tf_plan")
    assert missing is None
    assert all(r[sec_rules.WITNESS_ADDRESS_FIELD] ==
               "google_org_policy_policy.no_ext_ip" for r in records)
    rest, missing, _ = values_rows(
        rest_doc(LIST_DENY, P1,
                 rules=[{"values": {"allowedValues": ["projects/p1/x"]}}]),
        snap)
    assert missing is None
    assert all(sec_rules.WITNESS_ADDRESS_FIELD not in r for r in rest)
    # and the shared fields agree across the two transports
    strip = lambda row: {k: v for k, v in row.items()
                         if k != sec_rules.WITNESS_ADDRESS_FIELD}
    assert [strip(r) for r in records] == [strip(r) for r in rest]


def test_every_declared_field_is_on_every_row():
    """No row is ever ragged: every declared key is present, ``value`` is the
    honest empty string only on all_values rows."""
    snap = snapshot(
        set_policy(ORG, LIST_NODEF, rule(denied=("v",)), rule(allow_all=True)))
    doc = rest_doc(LIST_NODEF, P1, inherit=True, rules=[
        {"values": {"allowedValues": ["w"]}}])
    records, missing, _ = values_rows(doc, snap)
    assert missing is None
    declared = set(sec_ast.COLLECTIONS["effective_org_policy_values"].fields)
    for row in records:
        assert declared <= set(row)
    flag_rows = [r for r in records if r["all_values"]]
    assert flag_rows and all(r["value"] == "" for r in flag_rows)


def test_the_type_split_is_an_abstention_not_a_vacuous_pass():
    """A plan whose org-policy resources are all list-typed leaves the bool
    collection with a missing_reason (and symmetrically), mirroring
    ``_no_tf_records`` — never an empty instance a forall grounds over."""
    snap = snapshot()
    doc = plan(tf_resource("only_list", LIST_DENY, P1,
                           rules=[tf_rule(allowed=("v",))]))
    records, missing, _ = bool_rows(doc, snap, kind="tf_plan")
    assert records == ()
    assert "no boolean-typed constraint" in missing
    only_bool = plan(tf_resource("only_bool", BOOL_DENY, P1,
                                 rules=[tf_rule(enforce="TRUE")]))
    records, missing, _ = values_rows(only_bool, snap, kind="tf_plan")
    assert records == ()
    assert "no list-typed constraint" in missing


# -- captured-ness and completeness (A5-A10, A13) ------------------------------


def test_uncaptured_org_policies_abstains():
    snap = snapshot(drop=("org_policies",))
    records, missing, _ = bool_rows(rest_doc(BOOL_DENY), snap)
    assert records == ()
    assert "did not capture org_policies" in missing


def test_uncaptured_hierarchy_abstains():
    snap = snapshot(drop=("resource_hierarchy",))
    records, missing, _ = bool_rows(rest_doc(BOOL_DENY), snap)
    assert records == ()
    assert "did not capture resource_hierarchy" in missing


class _PartialView:
    """A ReconciledSnapshot-shaped stub: the wrapped snapshot's accessors plus
    a ``require_complete`` that refuses one named category."""

    def __init__(self, snap, category, reason):
        self._snap, self._category, self._reason = snap, category, reason

    def __getattr__(self, name):
        return getattr(self._snap, name)

    def require_complete(self, category, *, rule=None):
        return self._reason if category == self._category else None


def test_partial_org_policies_refused_with_the_reason_verbatim():
    """A9: the snapshot's own require_complete refusal surfaces verbatim."""
    view = _PartialView(snapshot(), "org_policies",
                        "category 'org_policies' has partial coverage")
    records, missing, _ = bool_rows(rest_doc(BOOL_DENY), view)
    assert records == ()
    assert "category 'org_policies' has partial coverage" in missing


def test_partial_hierarchy_refused():
    """A10 (MK-F13): absence in the hierarchy is READ (no policy at a node,
    no descendants), so a partial hierarchy may not license the fold."""
    view = _PartialView(snapshot(), "resource_hierarchy",
                        "category 'resource_hierarchy' has partial coverage")
    records, missing, _ = bool_rows(rest_doc(BOOL_DENY), view)
    assert records == ()
    assert "category 'resource_hierarchy' has partial coverage" in missing


def test_unknown_node_abstains():
    """A6: a node absent from the captured hierarchy has no chain to fold."""
    records, missing, _ = bool_rows(
        rest_doc(BOOL_DENY, "projects/ghost", rules=[{"enforce": True}]),
        snapshot())
    assert records == ()
    assert "projects/ghost" in missing and "not in the captured" in missing


def test_a_v1_document_names_no_node_and_abstains():
    """A5, the REST half: a v1 document's parent is the API call's."""
    doc = {"constraint": f"constraints/{BOOL_DENY}",
           "booleanPolicy": {"enforced": True}}
    records, missing, _ = bool_rows(doc, snapshot())
    assert records == ()
    assert "names no node" in missing


def test_constraint_value_type_unknowable_abstains():
    """A13, all three shapes: uncaptured constraints, an absent record, and a
    declared type outside boolean/list."""
    records, missing, _ = bool_rows(rest_doc(BOOL_DENY),
                                    snapshot(drop=("constraints",)))
    assert "value type" in missing and "unknowable" in missing
    records, missing, _ = bool_rows(rest_doc("no.suchConstraint"), snapshot())
    assert "record nothing for constraints/no.suchConstraint" in missing
    records, missing, _ = bool_rows(rest_doc("odd.unknownType"), snapshot())
    assert "value_type='unknown'" in missing


# -- the terraform arm's own refusals (A2-A5, A23-A25) -------------------------


def test_an_unreadable_plan_envelope_abstains():
    """A2, reused verbatim from the shared funnel."""
    records, missing, _ = bool_rows({"planned_values": 3,
                                     "resource_changes": "nope"},
                                    snapshot(), kind="tf_plan")
    assert records == ()
    assert "neither a readable 'planned_values'" in missing


def test_a_plan_with_no_org_policy_resource_abstains():
    """A3: a readable plan that carries nothing of this kind."""
    doc = plan({"address": "google_compute_firewall.x", "mode": "managed",
                "type": "google_compute_firewall",
                "provider_name": "registry.terraform.io/hashicorp/google",
                "values": {"name": "x"}})
    records, missing, _ = bool_rows(doc, snapshot(), kind="tf_plan")
    assert records == ()
    assert "carries no Org Policy resources" in missing


def test_an_org_policy_block_with_no_constraint_claim_aborts_by_census():
    """A4: a google_org_policy_policy block the claim walker read nothing
    from is a policy nobody read — named, never dropped beside a sibling."""
    broken = tf_resource("unreadable", BOOL_DENY, P1, name="")
    del broken["values"]["name"]
    doc = plan(broken)
    records, missing, _ = bool_rows(doc, snapshot(), kind="tf_plan")
    assert records == ()
    assert "google_org_policy_policy.unreadable" in missing
    assert "no constraint claim" in missing


def test_a_name_parent_disagreement_abstains():
    """A5, the terraform half: a block naming two nodes for one policy."""
    doc = plan(tf_resource("split", BOOL_DENY, P1, parent=FOLDER,
                           rules=[tf_rule(enforce="TRUE")]))
    records, missing, _ = bool_rows(doc, snapshot(), kind="tf_plan")
    assert records == ()
    assert "two nodes for one policy" in missing


def test_count_refuses_unknown_multiplicity():
    """A24, through the shared _resource_values refusal."""
    doc = plan(tf_resource("counted", BOOL_DENY, P1,
                           rules=[tf_rule(enforce="TRUE")],
                           extra_values={"count": 2}))
    records, missing, _ = bool_rows(doc, snapshot(), kind="tf_plan")
    assert records == ()
    assert "'count'" in missing


def test_an_unreadable_proposal_rule_abstains():
    """A23: a rule value the normalizer cannot read aborts by name."""
    doc = plan(tf_resource("garbled", BOOL_DENY, P1,
                           rules=[tf_rule(enforce="MAYBE")]))
    records, missing, _ = bool_rows(doc, snapshot(), kind="tf_plan")
    assert records == ()
    assert "enforce='MAYBE'" in missing


def test_two_resources_targeting_one_node_constraint_abstain():
    """A25: which one wins is an apply-order accident the fold will not
    guess."""
    doc = plan(tf_resource("one", BOOL_DENY, P1,
                           rules=[tf_rule(enforce="TRUE")]),
               tf_resource("two", BOOL_DENY, P1,
                           rules=[tf_rule(enforce="FALSE")]))
    records, missing, _ = bool_rows(doc, snapshot(), kind="tf_plan")
    assert records == ()
    assert "both target" in missing and "apply-order" in missing


def test_a_condition_block_on_a_proposal_rule_abstains():
    """A14, the proposal-rule variant: a tag-gated terraform rule."""
    doc = plan(tf_resource("gated", BOOL_DENY, P1,
                           rules=[dict(tf_rule(enforce="TRUE"),
                                       condition=[{"expression": "x"}])]))
    records, missing, _ = bool_rows(doc, snapshot(), kind="tf_plan")
    assert records == ()
    assert "condition" in missing


def test_an_off_kind_document_is_the_loud_default():
    """A1: an unsupported document kind abstains, never grounds vacuously."""
    records, missing, _ = bool_rows({"bindings": []}, snapshot(),
                                    kind="iam_policy")
    assert records == ()
    assert "not an org-policy document or a terraform plan" in missing


def test_the_evidence_floor_rewrites_unexplained_emptiness():
    """An extractor returning empty records with no reason is rewritten to a
    missing_reason by the shared floor — unreachable by construction here,
    asserted on a stub exactly as the design's test plan says."""
    records, missing, _ = sec_rules._normalize_extraction(
        "effective_org_policy_bool", ((), None))
    assert records == ()
    assert "did not say" in missing


# =============================================================================
# compiled promises over the effective collections
# =============================================================================


def fld(name, var="e"):
    return {"node": "field", "var": var, "field": name}


def lit(sort, value):
    return {"node": "lit", "sort": sort, "value": value}


def cmp(op, left, right):
    return {"node": "cmp", "op": op, "left": left, "right": right}


#: The design's first example promise: refute "the constraint is effectively
#: unenforced at ANY node the proposal determines".
STAYS_ENFORCED_AST = {
    "node": "exists", "var": "e", "collection": "effective_org_policy_bool",
    "body": {"node": "and", "args": [
        cmp("eq", fld("constraint"), lit("Str", BOOL_DENY)),
        cmp("eq", fld("enforce"), lit("Bool", False)),
    ]}}

#: The design's second example promise: refute "everything is effectively
#: allowed" for a list constraint.
NO_ALLOW_ALL_AST = {
    "node": "exists", "var": "e", "collection": "effective_org_policy_values",
    "body": {"node": "and", "args": [
        cmp("eq", fld("constraint"), lit("Str", LIST_DENY)),
        cmp("eq", fld("polarity"), lit("Str", "allow")),
        cmp("eq", fld("all_values"), lit("Bool", True)),
    ]}}


def promise(pid, mode, ast, *, vocabulary=()):
    source = sec_artifact.Source(
        file="orgeffective.md", line=3,
        text="the key-creation guardrail stays effectively enforced")
    if HAVE_Z3:
        formula, consts = sec_encode.symbolic(Z3, ast)
        obl = sec_probes.obligation(Z3, formula, mode)
        positive, negative = sec_probes.mint(Z3, obl, consts)
        assert positive is not None and negative is not None
        sexpr = formula.sexpr()
    else:
        sexpr = "(assert true)"
        positive = negative = {"placeholder": "x"}
    return sec_artifact.Promise(
        id=pid, source=source, domain="org_policy", mode=mode, state="estate",
        severity="high", vocabulary=tuple(vocabulary), ast=ast, sexpr=sexpr,
        free_consts=tuple(sec_ast.free_consts(ast)),
        positive=sec_artifact.Witness(assignment=positive, origin="z3-model"),
        negative=sec_artifact.Witness(assignment=negative, origin="z3-model"),
        wellformedness=sec_artifact.Wellformedness(satisfiable=True,
                                                   non_tautological=True),
        status="compiled", reason="")


def evaluate(mode, ast, document, snap, kind="org_policy", *, vocabulary=()):
    rule_obj = sec_rules.CompiledRule(
        promise=promise("effective-guardrail", mode, ast,
                        vocabulary=vocabulary))
    return rule_obj.evaluate(ctx(document, kind, snap))


def test_the_enforcement_promise_judges_the_three_worlds():
    """The §9 example promise end to end: refuted with a witness naming node
    and block on the violating world, grounded on the safe one, unverified on
    an abstention world."""
    snap = snapshot(set_policy(ORG, BOOL_DENY, rule(enforce=True)))
    violating = plan(tf_resource("disable", BOOL_DENY, P1,
                                 rules=[tf_rule(enforce="FALSE")]))
    safe = plan(tf_resource("keep", BOOL_DENY, P1,
                            rules=[tf_rule(enforce="TRUE")]))
    refuted = evaluate("refute", STAYS_ENFORCED_AST, violating, snap,
                       kind="tf_plan")
    grounded = evaluate("refute", STAYS_ENFORCED_AST, safe, snap,
                        kind="tf_plan")
    if not HAVE_Z3:
        assert refuted.status == grounded.status == "unverified"
        assert "z3 is not available" in refuted.message
    else:
        assert refuted.status == "contradicted"
        assert "effective_org_policy_bool[" in refuted.message
        assert "(google_org_policy_policy.disable)" in refuted.message
        assert f"node='{P1}'" in refuted.message
        assert grounded.status == "grounded"
    undecided = evaluate("refute", STAYS_ENFORCED_AST, violating,
                         snapshot(drop=("org_policies",)), kind="tf_plan")
    assert undecided.status == "unverified"
    assert "did not capture org_policies" in undecided.message


def test_a_folder_reset_is_caught_at_the_project_below():
    """The fold catches what no per-document view can: a folder-level reset
    whose disablement only materialises at the projects below it."""
    snap = snapshot(set_policy(ORG, BOOL_ALLOW, rule(enforce=True)))
    resetting = plan(tf_resource("reset", BOOL_ALLOW, FOLDER, reset=True))
    ast = {"node": "exists", "var": "e",
           "collection": "effective_org_policy_bool",
           "body": {"node": "and", "args": [
               cmp("eq", fld("constraint"), lit("Str", BOOL_ALLOW)),
               cmp("eq", fld("enforce"), lit("Bool", False)),
           ]}}
    # the fold's rows show the disablement at BOTH projects below the folder,
    # which no per-document view of the reset could see
    records, missing, _ = bool_rows(resetting, snap, kind="tf_plan")
    assert missing is None
    assert {(r["node"], r["enforce"]) for r in records} == {
        (FOLDER, False), (P1, False), (P2, False)}
    verdict = evaluate("refute", ast, resetting, snap, kind="tf_plan")
    if not HAVE_Z3:
        assert verdict.status == "unverified"
        return
    assert verdict.status == "contradicted"
    assert "(google_org_policy_policy.reset)" in verdict.message


def test_the_allow_all_promise_over_the_values_collection():
    snap = snapshot()
    widening = plan(tf_resource("open", LIST_DENY, P1,
                                rules=[tf_rule(allow_all="TRUE")]))
    narrow = plan(tf_resource("narrow", LIST_DENY, P1,
                              rules=[tf_rule(allowed=("projects/p1/ok",))]))
    refuted = evaluate("refute", NO_ALLOW_ALL_AST, widening, snap,
                       kind="tf_plan")
    grounded = evaluate("refute", NO_ALLOW_ALL_AST, narrow, snap,
                        kind="tf_plan")
    if not HAVE_Z3:
        assert refuted.status == grounded.status == "unverified"
        return
    assert refuted.status == "contradicted"
    assert "all_values=True" in refuted.message
    assert grounded.status == "grounded"


# -- the SUBJECTS set-generalization ------------------------------------------


def scoped_vocab(constraint):
    return (sec_artifact.VocabRef("constraint", f"constraints/{constraint}"),)


def test_a_scoped_promise_abstains_by_name_over_an_off_subject_plan():
    """A constraint-scoped promise over a plan that sets only a DIFFERENT
    constraint abstains naming both sides — never a vacuous verdict."""
    snap = snapshot()
    other = plan(tf_resource("other", LIST_DENY, P1,
                             rules=[tf_rule(allowed=("v",))]))
    verdict = evaluate("refute", STAYS_ENFORCED_AST, other, snap,
                       kind="tf_plan", vocabulary=scoped_vocab(BOOL_DENY))
    assert verdict.status == "unverified"
    assert BOOL_DENY in verdict.message and LIST_DENY in verdict.message
    assert "sets policies for the constraint" in verdict.message


def test_a_scoped_promise_abstains_by_name_over_an_off_subject_rest_doc():
    snap = snapshot()
    other = rest_doc(LIST_DENY, P1,
                     rules=[{"values": {"allowedValues": ["v"]}}])
    verdict = evaluate("refute", STAYS_ENFORCED_AST, other, snap,
                       kind="org_policy", vocabulary=scoped_vocab(BOOL_DENY))
    assert verdict.status == "unverified"
    assert BOOL_DENY in verdict.message and LIST_DENY in verdict.message


def test_an_on_subject_or_unscoped_promise_passes_the_gate():
    """Non-empty intersection, and an unscoped promise, keep today's route:
    the gate stays silent and the extractor's own answer speaks."""
    snap = snapshot(set_policy(ORG, BOOL_DENY, rule(enforce=True)))
    doc = plan(tf_resource("keep", BOOL_DENY, P1,
                           rules=[tf_rule(enforce="TRUE")]))
    on_subject = evaluate("refute", STAYS_ENFORCED_AST, doc, snap,
                          kind="tf_plan", vocabulary=scoped_vocab(BOOL_DENY))
    unscoped = evaluate("refute", STAYS_ENFORCED_AST, doc, snap,
                        kind="tf_plan")
    if HAVE_Z3:
        assert on_subject.status == "grounded"
        assert unscoped.status == "grounded"
    else:
        assert "z3 is not available" in on_subject.message


def test_a_plan_with_no_org_resource_keeps_the_extractor_abstention():
    """The undecidable-subjects sentinel: the gate stays SILENT for a plan
    with nothing of this kind, so the extractor's own named abstention speaks
    instead of a second, vaguer one."""
    snap = snapshot()
    doc = plan({"address": "google_compute_firewall.x", "mode": "managed",
                "type": "google_compute_firewall",
                "provider_name": "registry.terraform.io/hashicorp/google",
                "values": {"name": "x"}})
    verdict = evaluate("refute", STAYS_ENFORCED_AST, doc, snap,
                       kind="tf_plan", vocabulary=scoped_vocab(BOOL_DENY))
    assert verdict.status == "unverified"
    assert "carries no Org Policy resources" in verdict.message
    assert "sets policies for" not in verdict.message


# =============================================================================
# the document check (inert / blast radius, MK-F14)
# =============================================================================


def check(document, kind, snap, claims=()):
    context = CheckContext(snapshot=snap, solver=None, document=document,
                           document_kind=kind, source="proposal.json",
                           claims=tuple(claims))
    with evidence.ledger():
        return org_effective.check_org_effective(context)


def test_an_inert_proposal_gets_the_inert_finding():
    """A proposal restating the effective state is GROUNDED and loud: a
    guardrail that changes nothing is a signal reviewers need."""
    snap = snapshot(set_policy(P1, BOOL_NODEF, rule(enforce=True)))
    verdicts = check(rest_doc(BOOL_NODEF, P1, rules=[{"enforce": True}]),
                     "org_policy", snap)
    assert [v.status for v in verdicts] == ["grounded"]
    assert verdicts[0].kind == "org_effective"
    assert "INERT" in verdicts[0].message
    assert P1 in verdicts[0].message


def test_a_masked_org_level_enforce_is_inert_and_names_the_maskers():
    """The design's flagship inert case: an org-level enforce every project
    replaces LOOKS like a fix and is not."""
    snap = snapshot(
        set_policy(FOLDER, BOOL_NODEF, rule(enforce=True)),
        set_policy(P1, BOOL_NODEF, rule(enforce=False)),
        set_policy(P2, BOOL_NODEF, rule(enforce=False)))
    verdicts = check(rest_doc(BOOL_NODEF, FOLDER, rules=[{"enforce": True}]),
                     "org_policy", snap)
    assert [v.status for v in verdicts] == ["grounded"]
    assert "INERT" in verdicts[0].message
    assert P1 in verdicts[0].message and P2 in verdicts[0].message


def test_the_blast_radius_finding_lists_exactly_the_changed_nodes():
    snap = snapshot(
        set_policy(ORG, BOOL_NODEF, rule(enforce=True)),
        set_policy(P2, BOOL_NODEF, rule(enforce=True)))
    verdicts = check(rest_doc(BOOL_NODEF, FOLDER, rules=[{"enforce": False}]),
                     "org_policy", snap)
    assert [v.status for v in verdicts] == ["grounded"]
    message = verdicts[0].message
    assert "alters the effective state" in message
    # the folder and p1 flip; p2's own policy still decides there
    assert f"{FOLDER}: enforce true -> false" in message
    assert f"{P1}: enforce true -> false" in message
    assert P2 not in message.split("governs — ")[1]


def test_an_undecidable_fold_is_on_the_record_never_skipped():
    """MK-F14: an abstained before/after is exactly one ``unverified`` per
    target naming the cause — never a silent skip."""
    snap = snapshot(set_policy(ORG, BOOL_NODEF,
                               rule(enforce=True, condition="tag gated")))
    verdicts = check(rest_doc(BOOL_NODEF, P1, rules=[{"enforce": True}]),
                     "org_policy", snap)
    assert [v.status for v in verdicts] == ["unverified"]
    assert verdicts[0].kind == "org_effective"
    assert verdicts[0].target == f"constraints/{BOOL_NODEF}"
    assert "condition" in verdicts[0].message


def test_estate_level_refusals_are_one_named_abstention():
    verdicts = check(rest_doc(BOOL_NODEF, P1, rules=[{"enforce": True}]),
                     "org_policy", snapshot(drop=("org_policies",)))
    assert [v.status for v in verdicts] == ["unverified"]
    assert "did not capture org_policies" in verdicts[0].message


def test_the_check_is_silent_where_a_louder_abstention_already_speaks():
    """Nothing of this check's own: other document kinds, a hybrid document
    (preflight's zero-claims verdict speaks), and a plan whose claims carry
    no org-policy content (the tf-plan extractor's absence or a plan with
    none — preflight's story either way)."""
    snap = snapshot()
    assert check({"bindings": []}, "iam_policy", snap) == []
    hybrid = {"name": f"{P1}/policies/{BOOL_DENY}",
              "constraint": f"constraints/{BOOL_DENY}",
              "spec": {"rules": [{"enforce": True}]}}
    assert check(hybrid, "org_policy", snap) == []
    assert check(plan(tf_resource("x", BOOL_DENY, P1,
                                  rules=[tf_rule(enforce="TRUE")])),
                 "tf_plan", snap, claims=()) == []


def test_the_check_engages_a_plan_through_its_extracted_claims():
    from gcp_grounding import tf_claims

    doc = plan(tf_resource("keep", BOOL_DENY, P1,
                           rules=[tf_rule(enforce="TRUE")]))
    snap = snapshot(set_policy(P1, BOOL_DENY, rule(enforce=True)))
    claims = tf_claims.terraform_plan_claims(doc)
    verdicts = check(doc, "tf_plan", snap, claims=claims)
    assert [v.status for v in verdicts] == ["grounded"]
    assert "INERT" in verdicts[0].message
    assert "google_org_policy_policy.keep" in verdicts[0].message


# =============================================================================
# the additive constraint_default capture
# =============================================================================


def _request(payload):
    request = mock.Mock(name="request")
    request.execute.return_value = payload
    return request


def test_fetch_constraints_captures_the_constraint_default():
    orgpolicy = mock.Mock(name="orgpolicy")
    orgpolicy.organizations.return_value.constraints.return_value.list \
        .side_effect = [_request({"constraints": [
            {"name": f"{ORG}/constraints/iam.disableServiceAccountKeyCreation",
             "booleanConstraint": {}, "constraintDefault": "ALLOW"},
            {"name": f"{ORG}/constraints/compute.vmExternalIpAccess",
             "listConstraint": {}, "constraintDefault": "DENY"},
            {"name": f"{ORG}/constraints/example.odd",
             "booleanConstraint": {},
             "constraintDefault": "CONSTRAINT_DEFAULT_UNSPECIFIED"},
            {"name": f"{ORG}/constraints/example.silent",
             "booleanConstraint": {}}]})]
    fetched = fetch_constraints(orgpolicy, ORG)
    assert fetched["constraints/iam.disableServiceAccountKeyCreation"][
        "constraint_default"] == "ALLOW"
    assert fetched["constraints/compute.vmExternalIpAccess"][
        "constraint_default"] == "DENY"
    # an unrecognized spelling and an absent field are both OMITTED — the
    # fold then abstains by name rather than reading a guess
    assert "constraint_default" not in fetched["constraints/example.odd"]
    assert "constraint_default" not in fetched["constraints/example.silent"]
    # and the records are snapshot-ready
    GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:00:00Z",
                           "constraints": fetched})


def test_knowledge_rejects_an_unrecognized_constraint_default():
    with pytest.raises(ValueError, match="constraint_default"):
        GcpSnapshot.from_dict({
            "captured_at": "2026-07-18T09:00:00Z",
            "constraints": {"constraints/x.y": {
                "value_type": "boolean", "constraint_default": "MAYBE"}}})


def test_knowledge_round_trips_a_recognized_constraint_default():
    snap = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:00:00Z",
        "constraints": {"constraints/x.y": {
            "value_type": "boolean", "constraint_default": "DENY"}}})
    assert snap.constraint("constraints/x.y")["constraint_default"] == "DENY"
    assert snap.to_dict()["constraints"]["constraints/x.y"][
        "constraint_default"] == "DENY"


# =============================================================================
# registration
# =============================================================================


def test_the_two_effective_collections_are_registered_estate_tier():
    for name in ("effective_org_policy_bool", "effective_org_policy_values"):
        assert sec_ast.COLLECTIONS[name].tier == "estate"
        assert name in sec_rules.EXTRACTORS
    assert sec_domains.DOMAIN_COLLECTIONS["org_policy"] == (
        "effective_org_policy_bool", "effective_org_policy_values")
    assert sec_ast.COLLECTIONS["effective_org_policy_bool"].fields == {
        "node": "Str", "constraint": "Str", "enforce": "Bool"}
    assert sec_ast.COLLECTIONS["effective_org_policy_values"].fields == {
        "node": "Str", "constraint": "Str", "polarity": "Str",
        "value": "Str", "all_values": "Bool"}


def test_both_collections_map_to_the_org_policies_category():
    from gcp_grounding import provenance

    assert provenance.COLLECTION_CATEGORIES[
        "effective_org_policy_bool"] == "org_policies"
    assert provenance.COLLECTION_CATEGORIES[
        "effective_org_policy_values"] == "org_policies"


def test_extraction_is_solver_free_and_identical_on_both_backends():
    snap = snapshot(set_policy(ORG, BOOL_DENY, rule(enforce=True)))
    doc = rest_doc(BOOL_DENY, P1, rules=[{"enforce": False}])
    with_default = bool_rows(doc, snap)
    builtin_ctx = sec_rules.RuleContext(
        snapshot=snap, document=doc, document_kind="org_policy",
        solver=get_solver(prefer="builtin"))
    with_builtin = sec_rules._normalize_extraction(
        "effective_org_policy_bool",
        sec_rules.EXTRACTORS["effective_org_policy_bool"](builtin_ctx))
    assert with_default == with_builtin


# =============================================================================
# the parked mutation entries (activation debt, the deny-pair precedent)
# =============================================================================


@pytest.mark.xfail(strict=True,
                   reason="ORG-EFFECTIVE-REGISTER-ACTIVATION: the fourteen "
                          "MK-F entries are seeded PARKED "
                          "(mutation_entries.ORG_EFFECTIVE_ENTRIES) because "
                          "this work lands uncommitted and the frozen flip "
                          "test executes ACTIVE entries against a git-archive "
                          "copy where these anchors do not exist — the same "
                          "recorded constraint the deny pair's "
                          "ESC-DENY-REGISTER-ACTIVATION names. Moving them "
                          "into ENTRIES once this work is at HEAD makes this "
                          "node XPASS and forces a deliberate retirement.")
def test_the_org_effective_mutation_entries_are_active_in_the_register():
    from tests.mutation_contract import register
    seeded = {entry.id for entry in register()}
    required = {f"MK-F{n:02d}" for n in range(1, 15)}
    assert required <= seeded, sorted(required - seeded)
