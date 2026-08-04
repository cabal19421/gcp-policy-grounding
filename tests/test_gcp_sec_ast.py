"""Tests for the closed typed AST (:mod:`gcp_grounding.sec_ast`).

No parser exists yet, so ASTs are built as literal dicts. The suite covers every
node kind validating cleanly, each documented rejection raising the right
exception with the offending path named, canonical normal form, the analysis
helpers, and the lazy domain-resolution hook.
"""

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
