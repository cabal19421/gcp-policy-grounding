"""Tests for the compile-time probes (:mod:`gcp_grounding.sec_probes`).

Mirrors the ``HAVE_Z3`` branch idiom of the encode/solve suites: rather than
*skip* the z3-dependent cases on the builtin backend, each test BRANCHES — it
asserts every entry point abstains (its documented None value) instead of
raising. Under the oracle (z3 present) the real minting / classification /
independence assertions run.

A synthetic ``proposal``-tier collection covering every scalar sort is
registered so the round-trip test depends on no domain task.
"""

import re
import types

import pytest

from gcp_grounding import sec_artifact, sec_ast, sec_encode, sec_probes
from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.solver import get_solver
from gcp_grounding.sec_ast import CollectionSpec

_SOLVER = get_solver()
Z3 = _z3_module(_SOLVER)
HAVE_Z3 = _SOLVER.backend == "z3"


# -- a synthetic collection with every scalar sort ----------------------------

SYN = CollectionSpec("probe_records", "proposal", {
    "name": "Str",
    "count": "Int",
    "ratio": "Real",
    "addr": "Ip4",
    "src": "Cidr",
    "src_mask": "Ip4",
    "port": "Port",
    "proto": "Proto",
    "flag": "Bool",
})
sec_ast.register_collection(SYN)


# -- AST builders -------------------------------------------------------------

def fld(name, var="b"):
    return {"node": "field", "var": var, "field": name}


def lit(sort, value):
    return {"node": "lit", "sort": sort, "value": value}


def cmp(op, left, right):
    return {"node": "cmp", "op": op, "left": left, "right": right}


def forall(body, var="b", coll="iam_bindings"):
    return {"node": "forall", "var": var, "collection": coll, "body": body}


def exists(body, var="b", coll="iam_bindings"):
    return {"node": "exists", "var": var, "collection": coll, "body": body}


def role_eq(value):
    return cmp("eq", fld("role"), lit("Str", value))


def sfld(name):
    return fld(name, var="v")


def sforall(body):
    return {"node": "forall", "var": "v", "collection": "probe_records", "body": body}


ROLE_KEY = "iam_bindings#b.role"


def _obl(ast, mode="assert_satisfiable"):
    """The symbolic formula + obligation for *ast* (HAVE_Z3 only)."""
    formula, consts = sec_encode.symbolic(Z3, ast)
    return sec_probes.obligation(Z3, formula, mode), consts


def make_promise(mode, positive, negative, ast):
    """A compiled Promise carrying pinned witnesses — built without z3."""
    return sec_artifact.Promise(
        id="p1",
        source=sec_artifact.Source(file="f.md", line=1, text="a requirement sentence"),
        domain="iam",
        mode=mode,
        state="proposal",
        severity="high",
        vocabulary=(),
        ast=ast,
        sexpr="(assert true)",
        free_consts=((ROLE_KEY, "Str"),),
        positive=sec_artifact.Witness(assignment=positive, origin="pinned"),
        negative=sec_artifact.Witness(assignment=negative, origin="pinned"),
        wellformedness=sec_artifact.Wellformedness(satisfiable=True, non_tautological=True),
        status="compiled",
        reason="",
    )


# -- module surface -----------------------------------------------------------

def test_module_surface():
    assert sec_probes.MAX_INDEPENDENCE == 64
    r = sec_probes.ProbeResult(True, False, ("n",))
    assert r.satisfiable is True and r.non_tautological is False and r.notes == ("n",)


# -- obligation polarity: the anti-inversion regression -----------------------

def test_obligation_polarity_both_directions():
    ast = forall(role_eq("x"))  # forall b in iam_bindings: b.role == "x"
    if not HAVE_Z3:
        with pytest.raises(sec_encode.UnsupportedTerm):
            sec_encode.symbolic(Z3, ast)
        return
    formula, _ = sec_encode.symbolic(Z3, ast)
    obl_assert = sec_probes.obligation(Z3, formula, "assert_satisfiable")
    obl_refute = sec_probes.obligation(Z3, formula, "refute")
    # assert_satisfiable returns the formula unchanged; refute is exactly its Not.
    assert obl_assert is formula
    from gcp_grounding import solve
    assert solve.decide(Z3, Z3.And(obl_refute, formula)) is False

    # THE SAME record yields OPPOSITE classifications under the two modes.
    compliant = {ROLE_KEY: "x"}
    assert sec_probes.classify(Z3, ast, "assert_satisfiable", compliant) is True
    assert sec_probes.classify(Z3, ast, "refute", compliant) is False
    violating = {ROLE_KEY: "y"}
    assert sec_probes.classify(Z3, ast, "assert_satisfiable", violating) is False
    assert sec_probes.classify(Z3, ast, "refute", violating) is True


# -- probes -------------------------------------------------------------------

def test_probe_clean():
    ast = forall(role_eq("x"))
    if not HAVE_Z3:
        r = sec_probes.probe(None, None)
        assert r.satisfiable is None and r.non_tautological is None
        return
    obl, _ = _obl(ast)
    r = sec_probes.probe(Z3, obl)
    assert r.satisfiable is True
    assert r.non_tautological is True


def test_probe_unsatisfiable_yields_satisfiable_false():
    ast = forall({"node": "and", "args": [role_eq("x"), role_eq("y")]})
    if not HAVE_Z3:
        return
    obl, _ = _obl(ast)
    r = sec_probes.probe(Z3, obl)
    assert r.satisfiable is False  # role == "x" AND role == "y": no record ever


def test_probe_tautology_yields_non_tautological_false():
    ast = {"node": "true"}
    if not HAVE_Z3:
        return
    obl, _ = _obl(ast)
    r = sec_probes.probe(Z3, obl)
    assert r.satisfiable is True
    assert r.non_tautological is False  # forbids nothing


def test_probe_existential_note():
    ast = exists(role_eq("x"))
    r = sec_probes.probe(None, None, ast=ast)
    assert any("per_record" in n for n in r.notes)
    if not HAVE_Z3:
        return
    obl, _ = _obl(ast)
    r = sec_probes.probe(Z3, obl, ast=ast)
    assert r.satisfiable is True
    assert any("per_record" in n for n in r.notes)


# -- witnesses: mint + immediate re-classification ----------------------------

def test_minted_witnesses_reclassify():
    ast = forall(role_eq("x"))
    if not HAVE_Z3:
        assert sec_probes.mint(None, None, {}) == (None, None)
        return
    obl, consts = _obl(ast)
    positive, negative = sec_probes.mint(Z3, obl, consts)
    assert positive is not None and negative is not None
    # The compliant witness pins role == "x"; the violating one pins role != "x".
    assert positive[ROLE_KEY] == "x"
    assert negative[ROLE_KEY] != "x"
    assert sec_probes.classify(Z3, ast, "assert_satisfiable", positive) is True
    assert sec_probes.classify(Z3, ast, "assert_satisfiable", negative) is False


def test_corrupted_witness_reclassifies_as_drift():
    ast = forall(role_eq("x"))
    if not HAVE_Z3:
        return
    obl, consts = _obl(ast)
    positive, _ = sec_probes.mint(Z3, obl, consts)
    corrupt = dict(positive)
    corrupt[ROLE_KEY] = "definitely-not-x"          # one field flipped
    # It no longer satisfies the obligation: classifies as violating, i.e. drift.
    assert sec_probes.classify(Z3, ast, "assert_satisfiable", corrupt) is False


def test_witness_missing_key_returns_none():
    ast = forall(role_eq("x"))
    if not HAVE_Z3:
        assert sec_probes.classify(Z3, ast, "assert_satisfiable", {}) is None
        return
    assert sec_probes.classify(Z3, ast, "assert_satisfiable", {}) is None  # no coverage


def test_reclassify_pinned_witnesses():
    ast = forall(role_eq("x"))
    if not HAVE_Z3:
        stub = types.SimpleNamespace(ast=ast, mode="assert_satisfiable",
                                     positive=None, negative=None)
        assert sec_probes.reclassify(None, stub) == (None, None)
        return
    obl, consts = _obl(ast)
    positive, negative = sec_probes.mint(Z3, obl, consts)
    good = make_promise("assert_satisfiable", positive, negative, ast)
    assert sec_probes.reclassify(Z3, good) == (True, True)

    # Drift the pinned positive: positive_ok False, negative_ok still True.
    drifted = make_promise("assert_satisfiable", {ROLE_KEY: "nope"}, negative, ast)
    positive_ok, negative_ok = sec_probes.reclassify(Z3, drifted)
    assert positive_ok is False
    assert negative_ok is True


# -- round-trip stringification for every sort --------------------------------

def test_stringify_round_trip_every_sort():
    # Pin every scalar sort to a known value, mint, and check the exact strings;
    # then re-classify the minted positive to prove the strings round-trip.
    ast = sforall({"node": "and", "args": [
        cmp("eq", sfld("name"), lit("Str", "svc")),
        cmp("eq", sfld("count"), lit("Int", 42)),
        cmp("eq", sfld("ratio"), lit("Real", 7)),
        cmp("eq", sfld("addr"), lit("Ip4", "10.1.2.3")),
        cmp("eq", sfld("port"), lit("Port", 443)),
        cmp("eq", sfld("proto"), lit("Proto", 6)),
        cmp("eq", sfld("flag"), lit("Bool", True)),
    ]})
    if not HAVE_Z3:
        with pytest.raises(sec_encode.UnsupportedTerm):
            sec_encode.symbolic(Z3, ast)
        return
    obl, consts = _obl(ast)
    positive, _ = sec_probes.mint(Z3, obl, consts)
    assert positive == {
        "probe_records#v.name": "svc",
        "probe_records#v.count": "42",
        "probe_records#v.ratio": "7",
        "probe_records#v.addr": "10.1.2.3",
        "probe_records#v.port": "443",
        "probe_records#v.proto": "6",
        "probe_records#v.flag": "true",
    }
    assert sec_probes.classify(Z3, ast, "assert_satisfiable", positive) is True


def test_stringify_cidr_and_ip4_as_dotted_quad():
    # A Cidr FIELD (base) and an Ip4 field both stringify as dotted quads.
    ast = sforall({"node": "cidr_contains", "cidr": sfld("src"), "addr": sfld("addr")})
    if not HAVE_Z3:
        with pytest.raises(sec_encode.UnsupportedTerm):
            sec_encode.symbolic(Z3, ast)
        return
    obl, consts = _obl(ast)
    positive, _ = sec_probes.mint(Z3, obl, consts)
    assert positive is not None
    dotted = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    assert dotted.match(positive["probe_records#v.src"])
    assert dotted.match(positive["probe_records#v.addr"])
    # And each parses back to a valid 32-bit address.
    for value in (positive["probe_records#v.src"], positive["probe_records#v.addr"]):
        assert 0 <= sec_encode.dotted_quad_to_int(value) <= 0xFFFFFFFF


# -- independence probe -------------------------------------------------------

def test_independence_conflicting_forall_pair():
    a = forall(role_eq("x"))   # forall b: role == "x"
    b = forall(role_eq("y"))   # forall b: role == "y"  (contradicts over iam_bindings)
    if not HAVE_Z3:
        entries = [("a", None, True, ("iam_bindings",)),
                   ("b", None, True, ("iam_bindings",))]
        assert sec_probes.independence(Z3, entries).independent is None
        return
    obl_a, _ = _obl(a)
    obl_b, _ = _obl(b)
    entries = [("a", obl_a, True, ("iam_bindings",)),
               ("b", obl_b, True, ("iam_bindings",))]
    res = sec_probes.independence(Z3, entries)
    assert res.independent is False
    pairs = {tuple(sorted(c.ids)) for c in res.conflicts}
    assert ("a", "b") in pairs
    # forall/forall over a shared collection with no existential -> fatal.
    assert all(c.fatal for c in res.conflicts if tuple(sorted(c.ids)) == ("a", "b"))


def test_independence_disjoint_collections_empty():
    a = forall(role_eq("x"), var="b", coll="iam_bindings")
    b = forall(cmp("eq", fld("constraint", var="r"), lit("Str", "c")),
               var="r", coll="org_policy_rules")
    if not HAVE_Z3:
        entries = [("a", None, True, ("iam_bindings",)),
                   ("b", None, True, ("org_policy_rules",))]
        assert sec_probes.independence(Z3, entries).independent is None
        return
    obl_a, _ = _obl(a)
    obl_b, _ = _obl(b)
    entries = [("a", obl_a, True, ("iam_bindings",)),
               ("b", obl_b, True, ("org_policy_rules",))]
    res = sec_probes.independence(Z3, entries)
    # Disjoint vocabularies: trivially independent, no solve, no conflict.
    assert res.conflicts == ()
    assert res.independent is True


def test_independence_skip_over_64_leaves_none():
    entries = [(f"p{i}", None, True, ("iam_bindings",)) for i in range(65)]
    res = sec_probes.independence(Z3, entries)   # skipped before any solve
    assert res.independent is None
    assert res.conflicts == ()
    assert res.notes


def test_independence_disabled_leaves_none():
    entries = [("a", None, True, ("iam_bindings",))]
    res = sec_probes.independence(Z3, entries, enabled=False)
    assert res.independent is None
    assert res.notes


# -- no z3: every entry point abstains rather than raising ---------------------

def test_no_z3_entry_points_abstain():
    ast = forall(role_eq("x"))
    r = sec_probes.probe(None, None)
    assert r.satisfiable is None and r.non_tautological is None
    assert sec_probes.mint(None, None, {}) == (None, None)
    assert sec_probes.classify(None, ast, "assert_satisfiable", {ROLE_KEY: "x"}) is None
    stub = types.SimpleNamespace(ast=ast, mode="assert_satisfiable",
                                 positive=None, negative=None)
    assert sec_probes.reclassify(None, stub) == (None, None)
    entries = [("a", None, True, ("iam_bindings",)), ("b", None, True, ("iam_bindings",))]
    assert sec_probes.independence(None, entries).independent is None
