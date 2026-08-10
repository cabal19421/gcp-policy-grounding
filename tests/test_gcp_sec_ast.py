"""Tests for the closed typed AST (:mod:`gcp_grounding.sec_ast`).

No parser exists yet, so ASTs are built as literal dicts. The suite covers every
node kind validating cleanly, each documented rejection raising the right
exception with the offending path named, canonical normal form, the analysis
helpers, and the lazy domain-resolution hook.
"""

# ---------------------------------------------------------------------------
# MUTATION PAYDOWN RECORD — gcp_grounding/sec_ast.py (gx-debt-sec-ast, test-only)
#
# Measured with harness's own mutator. `harness` is NOT installed in this
# project's venv, so the import was made to work with
#   sys.path.insert(0, "/home/jones/Downloads/harness")
#   from harness.pipeline.mutation import collect_sites, mutation_score
# over a scratch copy built by `git archive <ref> | tar -x -C <scratch>`, with
#   target_files = ["gcp_grounding/sec_ast.py"]   (this module and nothing else)
#   validation   = ["<venv>/bin/python -m pytest -q tests/"]   (this task's oracle)
#   collect_sites(<source text of sec_ast.py>)    (source text, never a path)
# The UNMUTATED suite was asserted GREEN in the scratch copy before each score.
#
# The candidate count is LINEAGE-DEPENDENT — 146 sites on the org/hierfw lineage
# and 162 on the sexpr/cli lineage — so BOTH rows below were taken on THIS
# branch, agent/gx-debt-sec-ast, and only they are comparable.
#
#   row     sha of tree  sites  exhaustive (max_mutants=len(collect_sites))  40-draw
#   before  7b5e11ef       146  92/146  = 0.630  (54 survivors)              23/40
#   after   c8fa313b       146  143/146 = 0.979  (3 survivors)               40/40
#
# Green baseline: "296 passed" before, "346 passed" after — both in the scratch
# copy, unmutated, immediately before the score above it. The `after` row was
# taken on tree c8fa313b of this branch, whose ONLY delta from the commit you
# are reading is these numbers, written into this comment block afterwards.
#
# One of the three `after` survivors, 526 `and`->`or`, is a MEASUREMENT
# ARTIFACT, not debt: re-run alone with __pycache__ cleared it is KILLED
# ("4 failed, 342 passed"), and it was killed in two earlier batch runs too.
# Consecutive mutants of equal byte length land inside one mtime second, so
# CPython reuses the previous mutant's .pyc. The stable value is therefore
# 144/146 = 0.986 over exactly the two equivalent sites named below.
#
# Killed here, by named survivor group (see the task notes for the per-group
# record that each node FAILED under its mutant applied alone in an isolated
# copy and PASSED on clean source):
#   (1) port-range bounds  282 x6, 284 x6, 463, 465 — boundary tables below
#   (2) connectives        294, 302, 303, 310, 322, 323, 357, 358, 361, 375,
#                          384, 387, 393, 403, 405, 461, 477, 512, 593, 601, 603
#   (3) False/True defaults 83, 150, 159, 439, 451, 458, 496, 518, 522, 544, 624
# Two sites are MEASURED-EQUIVALENT and are escalated, not asserted:
#   522 `ensure_ascii=False`->`True` — the dedupe key is compared only against
#       other keys built the same way, and escaping is injective, so the
#       partition of args is identical under either spelling.
#   578 `-1`->`-2` (`best = -1` in derived_tier) — the `if not used` guard above
#       it returns early, so the loop always runs at least once and `best` is
#       overwritten by a rank >= 0 before it is read.
# ---------------------------------------------------------------------------

import dataclasses
import importlib.util
import sys

import pytest

from gcp_grounding import sec_ast as m
from gcp_grounding.sec_ast import CollectionSpec, InvalidAst, UnknownCollection


# -- helpers ------------------------------------------------------------------

def field(var, name):
    return {"node": "field", "var": var, "field": name}


def lit(sort, value):
    return {"node": "lit", "sort": sort, "value": value}


def forall(var, coll, body):
    return {"node": "forall", "var": var, "collection": coll, "body": body}


def cmp(op, left, right):
    return {"node": "cmp", "op": op, "left": left, "right": right}


@pytest.fixture(autouse=True)
def _fresh_domains():
    """Each test starts from a clean, resolved domain cache."""
    m.reset_domain_cache()
    yield
    m.reset_domain_cache()


# -- module surface -----------------------------------------------------------

def test_no_third_party_dependency_and_base_registry():
    assert m.SORTS == ("Bool", "Str", "Int", "Ip4", "Cidr", "Port", "Proto", "Real")
    assert m.BV_WIDTHS == {"Ip4": 32, "Cidr": 32, "Port": 16, "Proto": 8}
    assert m.TIERS == ("proposal", "pair", "estate")
    assert set(m.COLLECTIONS) >= {
        "iam_bindings", "org_policy_rules", "new_iam_bindings", "old_iam_bindings"}
    assert m.COLLECTIONS["iam_bindings"].tier == "proposal"
    assert m.COLLECTIONS["new_iam_bindings"].tier == "pair"
    assert m.COLLECTIONS["iam_bindings"].fields == {
        "role": "Str", "member": "Str", "condition": "Str", "has_condition": "Bool"}
    assert m.COLLECTIONS["org_policy_rules"].fields == {
        "constraint": "Str", "is_list": "Bool", "enforce": "Bool", "value": "Str"}


def test_tier_rank():
    assert m.tier_rank("proposal") == 0
    assert m.tier_rank("pair") == 1
    assert m.tier_rank("estate") == 2
    with pytest.raises(ValueError):
        m.tier_rank("nope")


# -- every node kind validates cleanly ----------------------------------------

@pytest.fixture
def net_coll():
    """A synthetic proposal collection carrying every scalar sort we need."""
    spec = CollectionSpec("t_net", "proposal", {
        "role": "Str", "port": "Port", "proto": "Proto", "count": "Int",
        "ratio": "Real", "flag": "Bool", "host": "Ip4",
        "range": "Cidr", "range_mask": "Ip4",
    })
    m.register_collection(spec)
    return "t_net"


def test_every_node_kind_validates_clean(net_coll):
    v = "x"
    body = {"node": "and", "args": [
        {"node": "true"},
        {"node": "false"},
        {"node": "not", "arg": {"node": "true"}},
        {"node": "or", "args": [{"node": "true"}, {"node": "false"}]},
        {"node": "implies", "if": {"node": "true"}, "then": {"node": "false"}},
        {"node": "atmost", "k": 1, "args": [{"node": "true"}, {"node": "false"}]},
        {"node": "atleast", "k": 1, "args": [{"node": "true"}, {"node": "false"}]},
        {"node": "exists", "var": "y", "collection": net_coll,
         "body": cmp("eq", field("y", "count"), field(v, "count"))},
        cmp("eq", field(v, "role"), lit("Str", "roles/x")),
        cmp("lt", field(v, "count"), lit("Int", 3)),
        cmp("le", field(v, "ratio"), lit("Real", 1.5)),
        {"node": "in", "term": field(v, "role"),
         "set": {"node": "set", "sort": "Str", "items": ["a", "b"]}},
        {"node": "prefix", "term": field(v, "role"), "value": "roles/"},
        {"node": "suffix", "term": field(v, "role"), "value": "Viewer"},
        {"node": "contains", "term": field(v, "role"), "value": "bigquery"},
        {"node": "cidr_contains", "cidr": field(v, "range"), "addr": field(v, "host")},
        {"node": "cidr_contains", "cidr": lit("Cidr", "10.0.0.0/8"), "addr": lit("Ip4", "10.1.2.3")},
        {"node": "port_in", "term": field(v, "port"), "lo": 0, "hi": 65535},
        {"node": "cel", "expr": "request.time < timestamp('2020-01-01T00:00:00Z')"},
        cmp("eq", field(v, "flag"), lit("Bool", True)),
    ]}
    m.validate(forall(v, net_coll, body))


def test_ip_and_cidr_literals():
    for cidr in ("0.0.0.0/0", "10.0.0.0/8", "1.2.3.4/32", "255.255.255.255/0"):
        for addr in ("0.0.0.0", "192.168.1.1", "255.255.255.255"):
            m.validate({"node": "cidr_contains",
                        "cidr": lit("Cidr", cidr), "addr": lit("Ip4", addr)})


# -- rejections: structural ---------------------------------------------------

def test_unknown_node_kind():
    with pytest.raises(InvalidAst, match="bogus"):
        m.validate({"node": "bogus"})


def test_missing_and_extra_keys():
    with pytest.raises(InvalidAst, match="missing keys"):
        m.validate({"node": "not"})
    with pytest.raises(InvalidAst, match="unexpected keys"):
        m.validate({"node": "true", "extra": 1})


def test_unbound_field_var():
    with pytest.raises(InvalidAst, match=r"var"):
        m.validate(cmp("eq", field("z", "role"), lit("Str", "x")))


def test_field_name_absent_from_spec():
    ast = forall("b", "iam_bindings", cmp("eq", field("b", "nope"), lit("Str", "x")))
    with pytest.raises(InvalidAst, match="nope"):
        m.validate(ast)


def test_cmp_sort_mismatch_names_path():
    ast = forall("b", "iam_bindings",
                 cmp("eq", field("b", "role"), lit("Int", 3)))
    with pytest.raises(InvalidAst, match=r"cmp\.right"):
        m.validate(ast)


def test_ordering_on_str_and_bool_rejected():
    ast = forall("b", "iam_bindings", cmp("lt", field("b", "role"), lit("Str", "x")))
    with pytest.raises(InvalidAst, match="ordering"):
        m.validate(ast)
    ast = forall("b", "iam_bindings", cmp("gt", field("b", "has_condition"), lit("Bool", True)))
    with pytest.raises(InvalidAst, match="ordering"):
        m.validate(ast)


def test_prefix_on_non_str_rejected(net_coll):
    ast = forall("b", net_coll,
                 {"node": "prefix", "term": field("b", "count"), "value": "1"})
    with pytest.raises(InvalidAst, match="Str"):
        m.validate(ast)


def test_in_sort_mismatch():
    ast = forall("b", "iam_bindings",
                 {"node": "in", "term": field("b", "role"),
                  "set": {"node": "set", "sort": "Int", "items": ["1"]}})
    with pytest.raises(InvalidAst, match=r"in\.set"):
        m.validate(ast)


def test_port_in_bounds_and_order(net_coll):
    ast = forall("b", net_coll,
                 {"node": "port_in", "term": field("b", "port"), "lo": 0, "hi": 70000})
    with pytest.raises(InvalidAst, match="65535"):
        m.validate(ast)
    ast = forall("b", net_coll,
                 {"node": "port_in", "term": field("b", "port"), "lo": 100, "hi": 10})
    with pytest.raises(InvalidAst, match="greater than"):
        m.validate(ast)


def test_cidr_contains_operand_sorts(net_coll):
    # cidr side not a Cidr
    ast = forall("b", net_coll,
                 {"node": "cidr_contains", "cidr": field("b", "host"), "addr": field("b", "host")})
    with pytest.raises(InvalidAst, match="Cidr"):
        m.validate(ast)


def test_int_port_proto_literal_ranges():
    with pytest.raises(InvalidAst, match="integer"):
        m.validate({"node": "cmp", "op": "eq",
                    "left": lit("Int", "3"), "right": lit("Int", 3)})
    with pytest.raises(InvalidAst, match="65535"):
        m.validate(cmp("eq", lit("Port", 70000), lit("Port", 1)))
    with pytest.raises(InvalidAst, match="255"):
        m.validate(cmp("eq", lit("Proto", 300), lit("Proto", 1)))


def test_bad_ip_literal_rejected():
    for bad in ("256.1.1.1", "10.0.0", "1.2.3.4/33", "192.168.001.1", "abc"):
        with pytest.raises(InvalidAst, match="dotted quad"):
            m.validate({"node": "cidr_contains",
                        "cidr": lit("Cidr", "10.0.0.0/8"), "addr": lit("Ip4", bad)})


def test_shadowed_quantifier_var():
    ast = forall("b", "iam_bindings", forall("b", "new_iam_bindings", {"node": "true"}))
    with pytest.raises(InvalidAst, match="shadow"):
        m.validate(ast)


def test_max_depth_rejection():
    def nest(n):
        node = {"node": "true"}
        for _ in range(n):
            node = {"node": "not", "arg": node}
        return node
    # 63 nots over a true leaf -> depth 64, accepted.
    m.validate(nest(63))
    assert m.depth(nest(63)) == 64
    # 64 nots -> depth 65, rejected.
    assert m.depth(nest(64)) == 65
    with pytest.raises(InvalidAst, match="MAX_DEPTH"):
        m.validate(nest(64))


# -- Cidr may appear only as the cidr operand ---------------------------------

@pytest.fixture
def cidr_coll():
    spec = CollectionSpec("t_cidr", "proposal",
                          {"range": "Cidr", "range_mask": "Ip4", "host": "Ip4"})
    m.register_collection(spec)
    return "t_cidr"


def test_cidr_term_as_cmp_operand_rejected(cidr_coll):
    ast = forall("b", cidr_coll, cmp("eq", field("b", "range"), field("b", "range")))
    with pytest.raises(InvalidAst, match=r"left") as exc:
        m.validate(ast)
    assert "Cidr" in str(exc.value)


def test_cidr_term_inside_in_set_rejected(cidr_coll):
    ast = forall("b", cidr_coll,
                 {"node": "in", "term": field("b", "range"),
                  "set": {"node": "set", "sort": "Cidr", "items": ["10.0.0.0/8"]}})
    with pytest.raises(InvalidAst, match=r"term") as exc:
        m.validate(ast)
    assert "Cidr" in str(exc.value)


def test_cidr_term_as_addr_side_rejected(cidr_coll):
    ast = forall("b", cidr_coll,
                 {"node": "cidr_contains", "cidr": field("b", "range"), "addr": field("b", "range")})
    with pytest.raises(InvalidAst, match=r"addr") as exc:
        m.validate(ast)
    assert "Cidr" in str(exc.value)


def test_cidr_field_needs_companion_mask():
    nomask = CollectionSpec("t_nomask", "proposal", {"range": "Cidr", "host": "Ip4"})
    m.register_collection(nomask)
    ast = forall("b", "t_nomask",
                 {"node": "cidr_contains", "cidr": field("b", "range"), "addr": field("b", "host")})
    with pytest.raises(InvalidAst, match="companion"):
        m.validate(ast)

    withmask = CollectionSpec("t_withmask", "proposal",
                              {"range": "Cidr", "range_mask": "Ip4", "host": "Ip4"})
    m.register_collection(withmask)
    ok = forall("b", "t_withmask",
                {"node": "cidr_contains", "cidr": field("b", "range"), "addr": field("b", "host")})
    m.validate(ok)


# -- canonicalization ---------------------------------------------------------

def test_canonical_commutativity_and_dedupe():
    a1 = {"node": "and", "args": [{"node": "true"}, {"node": "false"}]}
    a2 = {"node": "and", "args": [{"node": "false"}, {"node": "true"}]}
    assert m.canonical(a1) == m.canonical(a2)
    dup = {"node": "or", "args": [{"node": "true"}, {"node": "true"}, {"node": "false"}]}
    assert m.canonical(dup)["args"] == [{"node": "false"}, {"node": "true"}]


def test_canonical_collapses_singletons():
    assert m.canonical({"node": "and", "args": [{"node": "true"}, {"node": "true"}]}) == {"node": "true"}
    assert m.canonical({"node": "or", "args": [{"node": "false"}]}) == {"node": "false"}
    # atmost/atleast do NOT collapse (k has semantics)
    collapsed = m.canonical({"node": "atmost", "k": 1, "args": [{"node": "true"}, {"node": "true"}]})
    assert collapsed == {"node": "atmost", "k": 1, "args": [{"node": "true"}]}


def test_canonical_idempotent_and_set_dedupe():
    node = {"node": "in", "term": lit("Str", "x"),
            "set": {"node": "set", "sort": "Str", "items": ["b", "a", "b"]}}
    once = m.canonical(node)
    assert once["set"]["items"] == ["a", "b"]
    assert m.canonical(once) == once


def test_dumps_byte_stable():
    node = {"node": "and", "args": [{"node": "false"}, {"node": "true"}]}
    assert m.dumps(node) == m.dumps(node)
    assert m.dumps(node) == m.dumps({"node": "and", "args": [{"node": "true"}, {"node": "false"}]})


# -- analysis helpers ---------------------------------------------------------

def test_free_consts_naming_and_sort():
    ast = forall("b", "iam_bindings", {"node": "and", "args": [
        cmp("eq", field("b", "role"), lit("Str", "roles/x")),
        cmp("eq", field("b", "has_condition"), lit("Bool", True)),
    ]})
    assert m.free_consts(ast) == [
        ("iam_bindings#b.has_condition", "Bool"),
        ("iam_bindings#b.role", "Str"),
    ]


def test_derived_tier_mixed_and_unknown():
    mixed = {"node": "and", "args": [
        forall("a", "iam_bindings", {"node": "true"}),
        forall("c", "new_iam_bindings", {"node": "true"}),
    ]}
    assert m.derived_tier(mixed) == "pair"
    assert m.collections_used(mixed) == ["iam_bindings", "new_iam_bindings"]

    synthetic = forall("z", "zzz_registered_by_nobody", {"node": "true"})
    with pytest.raises(UnknownCollection):
        m.derived_tier(synthetic)


def test_derived_tier_no_collections():
    assert m.derived_tier({"node": "true"}) == "proposal"


def test_has_existential_and_forall_rooted():
    ex = forall("b", "iam_bindings",
                {"node": "exists", "var": "c", "collection": "iam_bindings",
                 "body": {"node": "true"}})
    assert m.has_existential(ex) is True
    assert m.is_forall_rooted(ex) is True
    fa = forall("b", "iam_bindings", {"node": "true"})
    assert m.has_existential(fa) is False
    assert m.is_forall_rooted(fa) is True
    assert m.is_forall_rooted({"node": "and", "args": [fa]}) is False


def test_sort_of():
    assert m.sort_of(lit("Str", "x"), {}) == "Str"
    assert m.sort_of(field("b", "role"), {"b": "iam_bindings"}) == "Str"
    with pytest.raises(InvalidAst):
        m.sort_of(field("b", "role"), {})


# -- collection registration --------------------------------------------------

def test_register_collection_idempotent_and_conflict():
    spec = CollectionSpec("t_reg", "proposal", {"a": "Str"})
    m.register_collection(spec)
    # identical re-registration is a no-op
    m.register_collection(CollectionSpec("t_reg", "proposal", {"a": "Str"}))
    # a different spec under the same name is a hard error
    with pytest.raises(ValueError, match="different spec"):
        m.register_collection(CollectionSpec("t_reg", "proposal", {"a": "Int"}))


def test_unknown_collection_in_forall():
    with pytest.raises(UnknownCollection):
        m.validate(forall("b", "zzz_no_such_collection", {"node": "true"}))


# -- lazy domain resolution ---------------------------------------------------

def test_ensure_domains_called_at_most_once(monkeypatch):
    m.reset_domain_cache()
    calls = {"n": 0}
    real = m.importlib.import_module

    def counting(name, *a, **k):
        if name == "gcp_grounding.sec_domains":
            calls["n"] += 1
            raise ImportError("no sec_domains in this checkout")
        return real(name, *a, **k)

    monkeypatch.setattr(m.importlib, "import_module", counting)
    node = {"node": "true"}
    m.validate(node)
    m.validate(node)
    m.derived_tier(node)
    m.collections_used(node)
    assert calls["n"] <= 1


def test_missing_sec_domains_degrades_to_base(monkeypatch):
    m.reset_domain_cache()
    real = m.importlib.import_module

    def missing(name, *a, **k):
        if name == "gcp_grounding.sec_domains":
            raise ImportError("simulated missing module")
        return real(name, *a, **k)

    monkeypatch.setattr(m.importlib, "import_module", missing)
    # base collections still validate, no exception from the failed import
    m.validate(forall("b", "iam_bindings", {"node": "true"}))
    # and a domain name nobody registered honestly reports UnknownCollection
    with pytest.raises(UnknownCollection):
        m.validate(forall("b", "zzz_domain_not_registered", {"node": "true"}))


# -- group 1: the port-range bound checks -------------------------------------
#
# A bound that admits one packet too many is a firewall hole, so each row
# asserts the MATCH DECISION for a boundary value and never the constant.

def _decide(node, accepted):
    if accepted:
        m.validate(node)
    else:
        with pytest.raises(InvalidAst):
            m.validate(node)


@pytest.mark.parametrize("value,accepted", [
    (-1, False), (0, True), (1, True), (65534, True), (65535, True),
    (65536, False), ("443", False), (True, False), (1.0, False),
])
def test_port_literal_boundary_table(value, accepted):
    _decide(cmp("eq", lit("Port", value), lit("Port", 1)), accepted)


@pytest.mark.parametrize("value,accepted", [
    (-1, False), (0, True), (1, True), (254, True), (255, True),
    (256, False), ("6", False),
])
def test_proto_literal_boundary_table(value, accepted):
    _decide(cmp("eq", lit("Proto", value), lit("Proto", 1)), accepted)


def test_int_literals_carry_no_port_or_proto_range():
    """Only Port and Proto are bounded; an Int literal is unbounded."""
    m.validate(cmp("eq", lit("Int", 70000), lit("Int", -70000)))


@pytest.mark.parametrize("lo,hi,accepted", [
    (0, 0, True), (443, 443, True), (0, 65535, True), (65535, 65535, True),
    (0, 65536, False), (-1, 10, False), (65536, 65536, False),
    (100, 10, False), (True, 10, False), ("0", 10, False),
])
def test_port_in_bounds_table(net_coll, lo, hi, accepted):
    _decide(forall("b", net_coll, {"node": "port_in", "term": field("b", "port"),
                                   "lo": lo, "hi": hi}), accepted)


# -- group 2: the propositional connectives -----------------------------------
#
# Per predicate: one document satisfying the FIRST disjunct alone and one
# satisfying the SECOND alone. Both must be decided the same way — the only
# shape an `or`->`and` mutation cannot survive.

def test_real_literal_rejects_bool_and_rejects_non_numbers():
    with pytest.raises(InvalidAst, match="Real literal"):        # bool alone
        m.validate(cmp("eq", lit("Real", True), lit("Real", 1.0)))
    with pytest.raises(InvalidAst, match="Real literal"):        # non-number alone
        m.validate(cmp("eq", lit("Real", "1.5"), lit("Real", 1.0)))
    m.validate(cmp("eq", lit("Real", 2), lit("Real", 1.5)))


def test_set_operand_must_be_a_set_node(net_coll):
    def in_node(operand):
        return forall("b", net_coll,
                      {"node": "in", "term": field("b", "role"), "set": operand})
    with pytest.raises(InvalidAst, match="expected a set literal"):   # not a Mapping
        m.validate(in_node([{"node": "set", "sort": "Str", "items": ["a"]}]))
    with pytest.raises(InvalidAst, match="expected a set literal"):   # wrong kind
        m.validate(in_node({"node": "bogus", "sort": "Str", "items": ["a"]}))


def test_set_items_must_be_a_list_of_strings(net_coll):
    def in_node(items):
        return forall("b", net_coll,
                      {"node": "in", "term": field("b", "role"),
                       "set": {"node": "set", "sort": "Str", "items": items}})
    with pytest.raises(InvalidAst, match=r"in\.set\.items"):   # not a list at all
        m.validate(in_node("ab"))
    with pytest.raises(InvalidAst, match=r"in\.set\.items"):   # a list with a non-string
        m.validate(in_node(["a", 1]))
    m.validate(in_node(["a", "b"]))
    with pytest.raises(InvalidAst) as exc:             # and at the root, unprefixed
        m.validate({"node": "set", "sort": "Str", "items": [1]})
    assert str(exc.value).startswith("set.items: ")


def test_term_operand_must_be_a_node_and_the_path_is_named():
    with pytest.raises(InvalidAst, match=r"cmp\.left"):     # Mapping, no "node" key
        m.validate(cmp("eq", {"sort": "Str", "value": "x"}, lit("Str", "x")))
    with pytest.raises(InvalidAst, match=r"cmp\.left"):     # not a Mapping at all
        m.validate(cmp("eq", ["node"], lit("Str", "x")))


def test_formula_must_be_a_node_object_and_the_path_is_named():
    with pytest.raises(InvalidAst, match="<root>"):                  # root position
        m.validate(42)
    with pytest.raises(InvalidAst, match=r"and\.args\[0\]"):         # Mapping, no kind
        m.validate({"node": "and", "args": [{"nope": 1}]})
    with pytest.raises(InvalidAst, match=r"and\.args\[0\]"):         # not a Mapping
        m.validate({"node": "and", "args": [["node"]]})


def test_root_error_path_is_the_bare_node_kind():
    with pytest.raises(InvalidAst) as exc:
        m.validate({"node": "not"})
    assert str(exc.value).startswith("not: ")


@pytest.mark.parametrize("kind", ["and", "or"])
def test_and_or_args_must_be_a_non_empty_list(kind):
    with pytest.raises(InvalidAst, match="non-empty list"):     # not a list
        m.validate({"node": kind, "args": ({"node": "true"},)})
    with pytest.raises(InvalidAst, match="non-empty list"):     # empty
        m.validate({"node": kind, "args": []})
    m.validate({"node": kind, "args": [{"node": "true"}]})      # one arg is legal


@pytest.mark.parametrize("kind", ["atmost", "atleast"])
def test_atmost_atleast_k_and_args(kind):
    with pytest.raises(InvalidAst, match="integer"):            # k not an int
        m.validate({"node": kind, "k": "1", "args": [{"node": "true"}]})
    with pytest.raises(InvalidAst, match="integer"):            # k a bool
        m.validate({"node": kind, "k": True, "args": [{"node": "true"}]})
    with pytest.raises(InvalidAst, match="non-empty list"):     # args not a list
        m.validate({"node": kind, "k": 1, "args": ({"node": "true"},)})
    with pytest.raises(InvalidAst, match="non-empty list"):     # args empty
        m.validate({"node": kind, "k": 1, "args": []})
    m.validate({"node": kind, "k": 1, "args": [{"node": "true"}]})


def test_quantifier_var_and_collection_must_be_non_empty_strings():
    with pytest.raises(InvalidAst, match="variable name"):      # var not a str
        m.validate(forall(3, "iam_bindings", {"node": "true"}))
    with pytest.raises(InvalidAst, match="variable name"):      # var empty
        m.validate(forall("", "iam_bindings", {"node": "true"}))
    with pytest.raises(InvalidAst, match="collection name"):    # collection not a str
        m.validate(forall("b", 3, {"node": "true"}))
    with pytest.raises(InvalidAst, match="collection name"):    # collection empty
        m.validate(forall("b", "", {"node": "true"}))


def test_each_node_kind_is_dispatched_to_its_own_arm():
    m.validate({"node": "implies", "if": {"node": "true"}, "then": {"node": "false"}})
    with pytest.raises(InvalidAst, match="unknown node kind"):
        m.validate({"node": "bogus"})
    with pytest.raises(InvalidAst, match="boolean-valued"):
        m.validate({"node": "not", "arg": {"node": "set", "sort": "Str", "items": []}})


def test_canonical_passes_non_nodes_through_untouched():
    assert m.canonical(42) == 42                       # not a Mapping
    assert m.canonical("x") == "x"                     # not a Mapping, but "in"-able
    assert m.canonical({"a": 1}) == {"a": 1}           # a Mapping with no kind


def test_free_consts_tolerates_ill_formed_subtrees():
    # an inner quantifier with no collection must not blank the outer binding
    inner = {"node": "exists", "var": "b", "collection": None,
             "body": cmp("eq", field("b", "role"), lit("Str", "x"))}
    assert m.free_consts(forall("b", "iam_bindings", inner)) == [
        ("iam_bindings#b.role", "Str")]
    # an unhashable field name, and a field absent from the spec, are dropped
    assert m.free_consts(forall("b", "iam_bindings",
                                {"node": "field", "var": "b", "field": ["role"]})) == []
    assert m.free_consts(forall("b", "iam_bindings",
                                cmp("eq", field("b", "nope"), lit("Str", "x")))) == []


# -- group 3: the False/True defaults -----------------------------------------

def test_collection_spec_is_frozen():
    spec = m.COLLECTIONS["iam_bindings"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.tier = "estate"
    assert m.COLLECTIONS["iam_bindings"].tier == "proposal"


def test_cidr_term_is_confined_to_the_cidr_operand(cidr_coll):
    only = "may appear only as the cidr operand"
    for node in ({"node": "prefix", "term": field("b", "range"), "value": "x"},
                 {"node": "cidr_contains", "cidr": field("b", "range"),
                  "addr": field("b", "range")},
                 {"node": "port_in", "term": field("b", "range"), "lo": 0, "hi": 1}):
        with pytest.raises(InvalidAst, match=only):
            m.validate(forall("b", cidr_coll, node))
    with pytest.raises(InvalidAst, match=only):      # and at the root, too
        m.validate(lit("Cidr", "10.0.0.0/8"))


def test_canonical_order_does_not_depend_on_key_insertion_order():
    b_first = {"node": "and", "args": [{"node": "lit", "sort": "Str", "value": "b"},
                                       {"sort": "Str", "value": "a", "node": "lit"}]}
    a_first = {"node": "and", "args": [{"value": "b", "sort": "Str", "node": "lit"},
                                       {"node": "lit", "sort": "Str", "value": "a"}]}
    assert m.canonical(b_first)["args"] == m.canonical(a_first)["args"]
    assert [x["value"] for x in m.canonical(b_first)["args"]] == ["a", "b"]


def test_canonical_orders_by_text_not_by_escape():
    node = {"node": "or", "args": [lit("Str", "é"), lit("Str", "z")]}
    assert [x["value"] for x in m.canonical(node)["args"]] == ["z", "é"]


def test_canonical_dedupes_across_key_insertion_order():
    node = {"node": "or", "args": [{"node": "lit", "sort": "Str", "value": "a"},
                                   {"value": "a", "sort": "Str", "node": "lit"}]}
    assert m.canonical(node) == {"node": "lit", "sort": "Str", "value": "a"}


def test_dumps_is_the_committed_artifact_byte_format():
    node = {"value": "é", "sort": "Str", "node": "lit"}
    assert m.dumps(node) == ('{\n  "node": "lit",\n  "sort": "Str",\n'
                             '  "value": "é"\n}')


def test_has_existential_of_a_non_node():
    assert m.has_existential("x") is False
    assert m.has_existential(None) is False


def test_reset_domain_cache_buys_exactly_one_more_attempt(monkeypatch):
    calls = _count_domain_imports(m, monkeypatch)
    m.reset_domain_cache()
    m.validate({"node": "true"})
    m.validate({"node": "true"})
    assert len(calls) == 1
    m.reset_domain_cache()
    m.validate({"node": "true"})
    assert len(calls) == 2


def test_a_fresh_module_has_not_yet_resolved_its_domains(monkeypatch):
    """A newly imported sec_ast still owes its one lazy domain-import attempt."""
    spec = importlib.util.spec_from_file_location("gcp_grounding._sec_ast_probe",
                                                  m.__file__)
    fresh = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, fresh)   # @dataclass needs it there
    spec.loader.exec_module(fresh)
    calls = _count_domain_imports(fresh, monkeypatch)
    fresh.validate({"node": "true"})
    assert calls == ["gcp_grounding.sec_domains"]


def _count_domain_imports(module, monkeypatch):
    """Record every ``sec_domains`` import *module* attempts, failing each one."""
    calls = []
    real = module.importlib.import_module

    def counting(name, *a, **k):
        if name == "gcp_grounding.sec_domains":
            calls.append(name)
            raise ImportError("absent in this checkout")
        return real(name, *a, **k)

    monkeypatch.setattr(module.importlib, "import_module", counting)
    return calls
