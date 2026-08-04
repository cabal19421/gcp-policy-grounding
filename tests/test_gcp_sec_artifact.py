"""Tests for the promise artifact schema (:mod:`gcp_grounding.sec_artifact`).

Docs are built in code (no compiler exists yet). The suite covers exact
round-trip, byte-stable and order-independent :func:`dumps`, every
``__post_init__`` invariant (each naming the promise id), strict rejection of
unknown keys at every nesting level, a bad schema, an AST over an unregistered
collection rejected on load, atomic writes that leave no ``.tmp`` behind, and
:func:`to_claims`.
"""

import copy

import pytest

from gcp_grounding import claims
from gcp_grounding import sec_artifact as m
from gcp_grounding.sec_artifact import (
    Promise, PromiseDoc, Source, VocabRef, Witness, Wellformedness,
)


# -- builders -----------------------------------------------------------------

def owner_ast():
    """A valid AST over the base ``iam_bindings`` collection (fresh each call)."""
    return {
        "node": "forall", "var": "b", "collection": "iam_bindings",
        "body": {
            "node": "cmp", "op": "eq",
            "left": {"node": "field", "var": "b", "field": "role"},
            "right": {"node": "lit", "sort": "Str", "value": "roles/owner"},
        },
    }


def compiled_promise(pid="check-owner", vocabulary=(VocabRef("role", "roles/owner"),)):
    return Promise(
        id=pid,
        source=Source("req.md", 12, "No binding may grant roles/owner."),
        domain="iam", mode="refute", state="proposal", severity="high",
        vocabulary=vocabulary,
        ast=owner_ast(),
        sexpr='(forall ((b Binding)) (not (= (role b) "roles/owner")))',
        free_consts=(("iam_bindings#b.role", "Str"),),
        positive=Witness({"iam_bindings#b.role": "roles/owner"}, "z3-model"),
        negative=Witness({"iam_bindings#b.role": "roles/viewer"}, "pinned"),
        wellformedness=Wellformedness(satisfiable=True, non_tautological=True,
                                      independent=None, notes=("probe skipped",)),
        status="compiled", reason="",
    )


def unverified_promise(pid="another-check"):
    return Promise(
        id=pid,
        source=Source("req.md", 20, "The list values must be enforced."),
        domain="org_policy", mode="assert_satisfiable", state="proposal",
        severity="low", status="unverified",
        reason="snapshot did not capture constraints",
        vocabulary_unverified=("constraints/foo",),
    )


def doc(*promises, source_doc="req.md"):
    return PromiseDoc(
        schema=m.SEC_SCHEMA,
        source_doc=source_doc,
        source_sha256="a" * 64,
        snapshot_captured_at="2026-01-01T00:00:00Z",
        encoder="sx-sec-encode/1",
        promises=promises or (compiled_promise(), unverified_promise()),
    )


# -- round-trip ---------------------------------------------------------------

def test_round_trip_exact():
    d = doc()
    assert PromiseDoc.from_dict(d.to_dict()) == d


def test_round_trip_through_file(tmp_path):
    d = doc()
    path = tmp_path / "compiled" / "req.promises.json"
    m.atomic_write(path, m.dumps(d))
    assert m.load(path) == d


# -- deterministic dump -------------------------------------------------------

def test_dumps_byte_identical_across_calls():
    d = doc()
    assert m.dumps(d) == m.dumps(d)
    assert m.dumps(d).endswith("\n")


def test_dumps_sorts_promises_by_id_regardless_of_order():
    forward = doc(compiled_promise("aaa"), unverified_promise("zzz"))
    reverse = doc(unverified_promise("zzz"), compiled_promise("aaa"))
    assert m.dumps(forward) == m.dumps(reverse)
    # the sorted tuple leads with the alphabetically-first id
    assert forward.promises[0].id == "aaa"
    assert [p.id for p in reverse.promises] == ["aaa", "zzz"]


# -- __post_init__ invariants (each names the promise id) ---------------------

def test_bad_id_rejected():
    with pytest.raises(ValueError, match="Bad_ID"):
        compiled_promise("Bad_ID")


@pytest.mark.parametrize("field_name, value", [
    ("mode", "nope"),
    ("domain", "not_a_domain"),
    ("state", "galaxy"),
    ("status", "greenlit"),
])
def test_bad_enum_field_rejected_with_id(field_name, value):
    with pytest.raises(ValueError, match="check-owner"):
        compiled_promise().__class__(
            **{**_kwargs(compiled_promise()), field_name: value})


def test_compiled_with_nonempty_reason_rejected():
    with pytest.raises(ValueError, match="check-owner"):
        Promise(**{**_kwargs(compiled_promise()), "reason": "should be empty"})


def test_rejected_status_with_empty_reason_rejected():
    with pytest.raises(ValueError, match="rej-1"):
        Promise(id="rej-1", source=Source("r.md", 1, "sentence"),
                domain="iam", mode="refute", state="proposal", severity="low",
                status="rejected", reason="")


def test_empty_source_text_rejected():
    with pytest.raises(ValueError, match="src-1"):
        Promise(id="src-1", source=Source("r.md", 1, ""),
                domain="iam", mode="refute", state="proposal", severity="low",
                status="unverified", reason="skipped")


def test_bad_vocabulary_kind_rejected():
    with pytest.raises(ValueError, match="check-owner"):
        compiled_promise(vocabulary=(VocabRef("cel", "1 < 2"),))


def test_compiled_missing_witness_rejected():
    with pytest.raises(ValueError, match="check-owner"):
        Promise(**{**_kwargs(compiled_promise()), "negative": None})


def test_compiled_missing_ast_rejected():
    with pytest.raises(ValueError, match="check-owner"):
        Promise(**{**_kwargs(compiled_promise()), "ast": None})


def test_compiled_empty_sexpr_rejected():
    with pytest.raises(ValueError, match="check-owner"):
        Promise(**{**_kwargs(compiled_promise()), "sexpr": ""})


def test_compiled_unsatisfiable_wellformedness_rejected():
    with pytest.raises(ValueError, match="check-owner"):
        Promise(**{**_kwargs(compiled_promise()),
                   "wellformedness": Wellformedness(satisfiable=False,
                                                    non_tautological=True)})


def test_bad_witness_origin_rejected():
    with pytest.raises(ValueError, match="origin"):
        Witness({"x": "1"}, "made-up")


def test_witness_assignment_must_be_strings():
    with pytest.raises(ValueError, match="string"):
        Witness({"x": 3}, "z3-model")


def test_probe_scope_must_be_per_record():
    with pytest.raises(ValueError, match="per_record"):
        Wellformedness(probe_scope="global")


def test_duplicate_ids_rejected():
    with pytest.raises(ValueError, match="dup"):
        doc(compiled_promise("dup"), unverified_promise("dup"))


# -- strict loading -----------------------------------------------------------

def test_unknown_document_key_rejected():
    data = doc().to_dict()
    data["bogus"] = 1
    with pytest.raises(ValueError, match="bogus"):
        PromiseDoc.from_dict(data)


def test_unknown_promise_key_rejected():
    data = doc().to_dict()
    data["promises"][0]["oops"] = True
    with pytest.raises(ValueError, match="oops"):
        PromiseDoc.from_dict(data)


def test_unknown_smt_key_rejected():
    data = doc().to_dict()
    data["promises"][0]["smt"]["weird"] = 1
    with pytest.raises(ValueError, match="weird"):
        PromiseDoc.from_dict(data)


def test_unknown_witnesses_key_rejected():
    data = doc().to_dict()
    data["promises"][0]["witnesses"]["extra"] = None
    with pytest.raises(ValueError, match="extra"):
        PromiseDoc.from_dict(data)


def test_unknown_wellformedness_key_rejected():
    data = doc().to_dict()
    data["promises"][0]["wellformedness"]["huh"] = 1
    with pytest.raises(ValueError, match="huh"):
        PromiseDoc.from_dict(data)


def test_unknown_witness_key_rejected():
    data = doc(compiled_promise()).to_dict()
    data["promises"][0]["witnesses"]["positive"]["junk"] = 1
    with pytest.raises(ValueError, match="junk"):
        PromiseDoc.from_dict(data)


def test_unknown_source_key_rejected():
    data = doc().to_dict()
    data["promises"][0]["source"]["nope"] = 1
    with pytest.raises(ValueError, match="nope"):
        PromiseDoc.from_dict(data)


def test_bad_schema_rejected_naming_expected():
    data = doc().to_dict()
    data["schema"] = "gcp-sec-promises/999"
    with pytest.raises(ValueError, match=m.SEC_SCHEMA):
        PromiseDoc.from_dict(data)


def test_unregistered_collection_ast_rejected_on_load(tmp_path):
    ghost = Promise(
        id="ghost", source=Source("r.md", 1, "a sentence"),
        domain="vpc_firewall", mode="refute", state="proposal", severity="low",
        ast={"node": "forall", "var": "x", "collection": "ghost_collection",
             "body": {"node": "true"}},
        status="unverified", reason="unsupported collection",
    )
    d = doc(ghost)
    path = tmp_path / "ghost.promises.json"
    m.atomic_write(path, m.dumps(d))
    with pytest.raises(ValueError) as exc:
        m.load(path)
    assert "ghost_collection" in str(exc.value)
    assert str(path) in str(exc.value)


# -- atomic_write -------------------------------------------------------------

def test_atomic_write_creates_parents_and_leaves_no_tmp(tmp_path):
    target = tmp_path / "deep" / "nested" / "x.promises.json"
    m.atomic_write(target, "payload\n")
    assert target.read_text(encoding="utf-8") == "payload\n"
    assert target.parent.is_dir()
    assert not (target.parent / "x.promises.json.tmp").exists()
    assert not list(tmp_path.rglob("*.tmp"))


def test_atomic_write_overwrites_existing(tmp_path):
    target = tmp_path / "x.json"
    m.atomic_write(target, "first")
    m.atomic_write(target, "second")
    assert target.read_text(encoding="utf-8") == "second"
    assert not list(tmp_path.rglob("*.tmp"))


# -- to_claims ----------------------------------------------------------------

def test_to_claims_produces_valid_claims_with_locations():
    p = compiled_promise(vocabulary=(
        VocabRef("role", "roles/owner"),
        VocabRef("permission", "compute.instances.get"),
    ))
    out = m.to_claims(p)
    assert [type(c) for c in out] == [claims.Claim, claims.Claim]
    assert (out[0].kind, out[0].value, out[0].location) == (
        "role", "roles/owner", "check-owner#vocabulary[0]")
    assert (out[1].kind, out[1].value, out[1].location) == (
        "permission", "compute.instances.get", "check-owner#vocabulary[1]")


def test_to_claims_empty_vocabulary():
    assert m.to_claims(unverified_promise()) == []


# -- helpers ------------------------------------------------------------------

def _kwargs(promise):
    """The constructor kwargs of *promise*, so a test can vary one field."""
    return {
        "id": promise.id, "source": promise.source, "domain": promise.domain,
        "mode": promise.mode, "state": promise.state, "severity": promise.severity,
        "vocabulary": promise.vocabulary, "ast": copy.deepcopy(promise.ast),
        "sexpr": promise.sexpr, "free_consts": promise.free_consts,
        "positive": promise.positive, "negative": promise.negative,
        "wellformedness": promise.wellformedness, "status": promise.status,
        "reason": promise.reason,
        "vocabulary_unverified": promise.vocabulary_unverified,
        "notes": promise.notes,
    }
