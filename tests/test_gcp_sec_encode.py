"""Tests for the AST→z3 encoder (:mod:`gcp_grounding.sec_encode`).

The suite honours the environment: ``HAVE_Z3`` mirrors the runtime's own
degradation (``get_solver().backend == "z3"``). Rather than *skip* the
z3-dependent cases when the backend is the builtin fallback, each test BRANCHES —
it asserts the encoder abstains with :class:`UnsupportedTerm`, never a silent
pass. Under the oracle (z3 present) the real symbolic/ground assertions run.

A synthetic estate-tier collection is registered here so the CIDR and port cases
depend on no domain task.
"""

import pytest

from gcp_grounding import sec_ast, sec_encode
from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.solver import get_solver
from gcp_grounding.sec_ast import CollectionSpec
from gcp_grounding.sec_encode import (
    UnsupportedTerm,
    dotted_quad_to_int,
    ground,
    parse_cidr,
    symbolic,
    z3_literal,
    z3_sort,
)

_SOLVER = get_solver()
Z3 = _z3_module(_SOLVER)
HAVE_Z3 = _SOLVER.backend == "z3"


# -- synthetic collection -----------------------------------------------------

# Every scalar sort plus a Cidr field and its mandatory Ip4 companion, so a
# Cidr-sorted FIELD can be the cidr operand of cidr_contains.
SYN = CollectionSpec("syn_packets", "estate", {
    "src": "Cidr",
    "src_mask": "Ip4",
    "addr": "Ip4",
    "port": "Port",
    "proto": "Proto",
    "name": "Str",
    "count": "Int",
    "ratio": "Real",
    "flag": "Bool",
})
sec_ast.register_collection(SYN)


# -- AST builders -------------------------------------------------------------

def fld(name):
    return {"node": "field", "var": "v", "field": name}


def lit(sort, value):
    return {"node": "lit", "sort": sort, "value": value}


def q(body):
    return {"node": "forall", "var": "v", "collection": "syn_packets", "body": body}


def qe(body):
    return {"node": "exists", "var": "v", "collection": "syn_packets", "body": body}


def cmp(op, left, right):
    return {"node": "cmp", "op": op, "left": left, "right": right}


def name_eq(s):
    return cmp("eq", fld("name"), lit("Str", s))


# -- z3 decision helpers (only called under HAVE_Z3) --------------------------

def is_valid(formula):
    """A closed formula is *true* iff its negation is unsatisfiable."""
    s = Z3.Solver()
    s.add(Z3.Not(formula))
    return s.check() == Z3.unsat


def is_unsat(formula):
    """A closed formula is *false* iff it is unsatisfiable."""
    s = Z3.Solver()
    s.add(formula)
    return s.check() == Z3.unsat


def var_names(formula):
    from z3 import z3util
    return {v.decl().name() for v in z3util.get_vars(formula)}


def free_names(ast):
    return {name for name, _ in sec_ast.free_consts(ast)}


# -- module surface -----------------------------------------------------------

def test_module_surface():
    assert sec_encode.MAX_DEPTH == 64
    assert sec_encode.MAX_UNROLL == 10_000
    assert sec_encode.ENCODER_VERSION == "gcp-sec-encode/1"
    for kind in ("true", "false", "and", "or", "not", "implies", "atmost",
                 "atleast", "forall", "exists", "cmp", "in", "prefix", "suffix",
                 "contains", "cidr_contains", "port_in", "cel"):
        assert kind in sec_encode.ENCODERS


# -- parse helpers (no z3 required) -------------------------------------------

def test_dotted_quad_to_int_strict():
    assert dotted_quad_to_int("10.1.2.3") == 0x0A010203
    assert dotted_quad_to_int("0.0.0.0") == 0
    assert dotted_quad_to_int("255.255.255.255") == 0xFFFFFFFF
    for bad in ("10.0.0.01", "256.0.0.0", "10.0.0", "10.0.0.0/8", "", "ten", None):
        with pytest.raises(UnsupportedTerm):
            dotted_quad_to_int(bad)


def test_parse_cidr_strict():
    assert parse_cidr("10.0.0.0/8") == (0x0A000000, 0xFF000000)
    assert parse_cidr("0.0.0.0/0") == (0, 0)
    assert parse_cidr("192.168.1.0/24") == (0xC0A80100, 0xFFFFFF00)
    assert parse_cidr("10.0.0.5") == (0x0A000005, 0xFFFFFFFF)  # bare address -> /32
    for bad in ("10.0.0.0/33", "10.0.0.0/", "256.0.0.0/8", "10.0.0.01/8", "", None):
        with pytest.raises(UnsupportedTerm):
            parse_cidr(bad)


# -- sort / literal construction ----------------------------------------------

def test_z3_sort_and_literal():
    if not HAVE_Z3:
        # With no z3 module the sort/literal builders are never reached — the
        # entry points abstain first. Assert that abstention is honest.
        with pytest.raises(UnsupportedTerm):
            symbolic(Z3, q(name_eq("x")))
        return
    assert z3_sort(Z3, "Bool").eq(Z3.BoolSort())
    assert z3_sort(Z3, "Str").eq(Z3.StringSort())
    assert z3_sort(Z3, "Int").eq(Z3.IntSort())
    assert z3_sort(Z3, "Real").eq(Z3.RealSort())
    assert z3_sort(Z3, "Ip4").eq(Z3.BitVecSort(32))
    assert z3_sort(Z3, "Cidr").eq(Z3.BitVecSort(32))
    assert z3_sort(Z3, "Port").eq(Z3.BitVecSort(16))
    assert z3_sort(Z3, "Proto").eq(Z3.BitVecSort(8))

    assert z3_literal(Z3, "Str", "hi").eq(Z3.StringVal("hi"))
    assert z3_literal(Z3, "Bool", True).eq(Z3.BoolVal(True))
    assert z3_literal(Z3, "Int", 5).eq(Z3.IntVal(5))
    assert z3_literal(Z3, "Real", 1.5).eq(Z3.RealVal(1.5))
    assert z3_literal(Z3, "Ip4", "10.0.0.1").eq(Z3.BitVecVal(0x0A000001, 32))
    assert z3_literal(Z3, "Port", 443).eq(Z3.BitVecVal(443, 16))
    assert z3_literal(Z3, "Proto", 6).eq(Z3.BitVecVal(6, 8))
    # A CIDR is never a scalar operand.
    with pytest.raises(UnsupportedTerm):
        z3_literal(Z3, "Cidr", "10.0.0.0/8")


# -- symbolic: each node kind -------------------------------------------------

def _each_node_kind_asts():
    return {
        "true": {"node": "true"},
        "false": {"node": "false"},
        "and": q({"node": "and", "args": [name_eq("a"), name_eq("b")]}),
        "or": q({"node": "or", "args": [name_eq("a"), name_eq("b")]}),
        "not": q({"node": "not", "arg": name_eq("a")}),
        "implies": q({"node": "implies", "if": name_eq("a"), "then": name_eq("b")}),
        "atmost": q({"node": "atmost", "k": 1, "args": [name_eq("a"), name_eq("b")]}),
        "atleast": q({"node": "atleast", "k": 1, "args": [name_eq("a"), name_eq("b")]}),
        "cmp": q(cmp("gt", fld("port"), lit("Port", 100))),
        "in": q({"node": "in", "term": fld("name"),
                 "set": {"node": "set", "sort": "Str", "items": ["a", "b"]}}),
        "prefix": q({"node": "prefix", "term": fld("name"), "value": "pre"}),
        "suffix": q({"node": "suffix", "term": fld("name"), "value": "suf"}),
        "contains": q({"node": "contains", "term": fld("name"), "value": "mid"}),
        "cidr_contains": q({"node": "cidr_contains",
                            "cidr": lit("Cidr", "10.0.0.0/8"), "addr": fld("addr")}),
        "port_in": q({"node": "port_in", "term": fld("port"), "lo": 20, "hi": 80}),
        "exists": qe(name_eq("a")),
    }


def test_symbolic_each_node_kind():
    asts = _each_node_kind_asts()
    if not HAVE_Z3:
        for ast in asts.values():
            with pytest.raises(UnsupportedTerm):
                symbolic(Z3, ast)
        return
    for kind, ast in asts.items():
        formula, consts = symbolic(Z3, ast)
        assert formula.sexpr(), f"{kind}: empty sexpr"
        # free consts of the formula match sec_ast.free_consts exactly, and the
        # returned mapping is ordered by sorted name.
        assert set(consts) == free_names(ast), kind
        assert list(consts) == sorted(consts), kind


def test_symbolic_free_vars_regression():
    # The regression that matters: no encoder may quietly reintroduce a free
    # symbol (the cel-style z3.Real("request.time") bug). get_vars over the
    # symbolic formula must equal exactly sec_ast.free_consts.
    ast = q({"node": "and", "args": [
        name_eq("x"),
        {"node": "port_in", "term": fld("port"), "lo": 20, "hi": 80},
        {"node": "cidr_contains", "cidr": lit("Cidr", "10.0.0.0/8"), "addr": fld("addr")},
        {"node": "prefix", "term": fld("name"), "value": "pre"},
        {"node": "in", "term": fld("proto"),
         "set": {"node": "set", "sort": "Proto", "items": ["6", "17"]}},
        {"node": "not", "arg": cmp("gt", fld("count"), lit("Int", 5))},
        cmp("le", fld("ratio"), lit("Real", 1.5)),
        cmp("eq", fld("flag"), lit("Bool", True)),
    ]})
    if not HAVE_Z3:
        with pytest.raises(UnsupportedTerm):
            symbolic(Z3, ast)
        return
    formula, consts = symbolic(Z3, ast)
    assert var_names(formula) == free_names(ast)
    assert set(consts) == free_names(ast)


# -- ground: unrolling over 0, 1, 3 records -----------------------------------

def test_ground_unroll_empty_one_three():
    fa = q(name_eq("x"))
    ex = qe(name_eq("x"))
    if not HAVE_Z3:
        with pytest.raises(UnsupportedTerm):
            ground(Z3, fa, {"syn_packets": []})
        return
    # empty collection: forall -> True, exists -> False
    assert is_valid(ground(Z3, fa, {"syn_packets": []}))
    assert is_unsat(ground(Z3, ex, {"syn_packets": []}))
    # one record
    assert is_valid(ground(Z3, fa, {"syn_packets": [{"name": "x"}]}))
    # three matching records
    three_ok = {"syn_packets": [{"name": "x"}, {"name": "x"}, {"name": "x"}]}
    assert is_valid(ground(Z3, fa, three_ok))
    # three records, one violates: forall False, exists True
    mixed = {"syn_packets": [{"name": "x"}, {"name": "y"}, {"name": "x"}]}
    assert is_unsat(ground(Z3, fa, mixed))
    assert is_valid(ground(Z3, ex, mixed))


# -- cidr_contains ------------------------------------------------------------

def test_cidr_contains_literal():
    match_8 = q({"node": "cidr_contains",
                 "cidr": lit("Cidr", "10.0.0.0/8"), "addr": fld("addr")})
    match_any = q({"node": "cidr_contains",
                   "cidr": lit("Cidr", "0.0.0.0/0"), "addr": fld("addr")})
    if not HAVE_Z3:
        with pytest.raises(UnsupportedTerm):
            ground(Z3, match_8, {"syn_packets": [{"addr": "10.1.2.3"}]})
        return
    assert is_valid(ground(Z3, match_8, {"syn_packets": [{"addr": "10.1.2.3"}]}))
    assert is_unsat(ground(Z3, match_8, {"syn_packets": [{"addr": "11.0.0.1"}]}))
    # 0.0.0.0/0 matches every address.
    for addr in ("10.1.2.3", "11.0.0.1", "255.255.255.255", "0.0.0.0"):
        assert is_valid(ground(Z3, match_any, {"syn_packets": [{"addr": addr}]}))


def test_cidr_field_operand_both_modes():
    # A Cidr-sorted FIELD as the cidr operand — the shape a single z3_literal
    # path could not express — supplied as a field-plus-_mask pair.
    ast = q({"node": "cidr_contains", "cidr": fld("src"), "addr": fld("addr")})
    hit = {"syn_packets": [{"src": "10.0.0.0", "src_mask": "255.0.0.0", "addr": "10.1.2.3"}]}
    miss = {"syn_packets": [{"src": "10.0.0.0", "src_mask": "255.0.0.0", "addr": "11.0.0.1"}]}
    if not HAVE_Z3:
        with pytest.raises(UnsupportedTerm):
            ground(Z3, ast, hit)
        with pytest.raises(UnsupportedTerm):
            symbolic(Z3, ast)
        return
    # ground: 10.0.0.0/255.0.0.0 matches 10.1.2.3 but not 11.0.0.1
    assert is_valid(ground(Z3, ast, hit))
    assert is_unsat(ground(Z3, ast, miss))
    # symbolic: the Ip4 companion is wired as a BitVec(32) symbol even though it
    # is not itself a free_const.
    formula, consts = symbolic(Z3, ast)
    assert formula.sexpr()
    assert {"syn_packets#v.src", "syn_packets#v.src_mask",
            "syn_packets#v.addr"} <= var_names(formula)
    assert set(consts) == {"syn_packets#v.src", "syn_packets#v.addr"}


# -- port_in / unsigned comparison --------------------------------------------

def test_port_in():
    ast = q({"node": "port_in", "term": fld("port"), "lo": 22, "hi": 22})
    if not HAVE_Z3:
        with pytest.raises(UnsupportedTerm):
            ground(Z3, ast, {"syn_packets": [{"port": 22}]})
        return
    assert is_valid(ground(Z3, ast, {"syn_packets": [{"port": 22}]}))
    assert is_unsat(ground(Z3, ast, {"syn_packets": [{"port": 21}]}))


def test_unsigned_comparison():
    # port 40000 has the high bit set: unsigned 40000 > 100 is True; a SIGNED
    # 16-bit comparison would read 40000 as negative and get it wrong.
    ast = q(cmp("gt", fld("port"), lit("Port", 100)))
    if not HAVE_Z3:
        with pytest.raises(UnsupportedTerm):
            ground(Z3, ast, {"syn_packets": [{"port": 40000}]})
        return
    assert is_valid(ground(Z3, ast, {"syn_packets": [{"port": 40000}]}))
    assert is_unsat(ground(Z3, ast, {"syn_packets": [{"port": 50}]}))


# -- cel refusal --------------------------------------------------------------

CEL = {"node": "cel", "expr": 'request.time < timestamp("2020-01-01T00:00:00Z")'}


def test_cel_refused_symbolic():
    with pytest.raises(UnsupportedTerm) as info:
        symbolic(Z3, q(CEL))
    if HAVE_Z3:
        assert "cel" in str(info.value)


def test_cel_refused_ground():
    with pytest.raises(UnsupportedTerm) as info:
        ground(Z3, q(CEL), {"syn_packets": [{"name": "x"}]})
    if HAVE_Z3:
        assert "cel" in str(info.value)


# -- ground record faults abstain ---------------------------------------------

def test_ground_missing_none_wrongtype_raise():
    ast = q(name_eq("x"))
    for inst in ({"syn_packets": [{}]},                  # missing key
                 {"syn_packets": [{"name": None}]},      # None
                 {"syn_packets": [{"name": 5}]}):         # wrong Python type
        with pytest.raises(UnsupportedTerm):
            ground(Z3, ast, inst)


def test_ground_absent_collection_raises():
    ast = q(name_eq("x"))
    with pytest.raises(UnsupportedTerm):
        ground(Z3, ast, {})  # syn_packets referenced but absent


def test_ground_max_unroll_raises():
    ast = q({"node": "true"})
    big = {"syn_packets": [{}] * (sec_encode.MAX_UNROLL + 1)}
    with pytest.raises(UnsupportedTerm):
        ground(Z3, ast, big)


# -- None backend degrades ----------------------------------------------------

def test_none_backend_abstains():
    # Passing z3=None (the builtin backend) abstains in both modes, in every
    # environment — the documented None-module handling, never a silent pass.
    ast = q(name_eq("x"))
    with pytest.raises(UnsupportedTerm):
        symbolic(None, ast)
    with pytest.raises(UnsupportedTerm):
        ground(None, ast, {"syn_packets": [{"name": "x"}]})


# -- encoder override hook ----------------------------------------------------

def test_register_encoder_override():
    ast = q({"node": "port_in", "term": fld("port"), "lo": 22, "hi": 22})
    inst = {"syn_packets": [{"port": 22}]}  # normally satisfies port_in 22..22
    original = sec_encode.ENCODERS["port_in"]

    def always_false(z3, node, resolver, env, depth):
        return z3.BoolVal(False)

    try:
        sec_encode.register_encoder("port_in", always_false)
        assert sec_encode.ENCODERS["port_in"] is always_false
        if not HAVE_Z3:
            with pytest.raises(UnsupportedTerm):
                ground(Z3, ast, inst)
        else:
            # The override supersedes the built-in: the result is now False.
            assert is_unsat(ground(Z3, ast, inst))
    finally:
        sec_encode.register_encoder("port_in", original)
    assert sec_encode.ENCODERS["port_in"] is original
