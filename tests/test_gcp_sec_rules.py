"""Tests for stage 2 (:mod:`gcp_grounding.sec_rules`).

Uses the ``HAVE_Z3`` branch idiom of the encode/probes/solve suites: rather than
*skip* the z3-dependent cases on the builtin backend, each test BRANCHES — it
asserts the documented builtin behaviour (every rule abstains ``unverified``, a
tampered artifact registers with an integrity note) when z3 is absent, and the
real grounded/contradicted/refusal assertions when z3 is present.

Promises are built in code (via minted or placeholder ``Promise`` objects) so the
suite depends on no ``sx-sec-compile`` stage-1 code, plus ``tmp_path`` artifacts
for the loader and anti-tamper pins.
"""

import dataclasses
import json
from pathlib import Path

import pytest

from gcp_grounding import sec_artifact, sec_ast, sec_encode, sec_probes, sec_rules
from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.sec_ast import CollectionSpec

_SOLVER = get_solver()
Z3 = _z3_module(_SOLVER)
HAVE_Z3 = _SOLVER.backend == "z3"

SNAP = GcpSnapshot(captured_at="2026-01-01T00:00:00Z")

ROLE_KEY = "iam_bindings#b.role"
MEMBER_KEY = "iam_bindings#b.member"


# -- a synthetic estate collection (no extractor by default) ------------------

EST = CollectionSpec("syn_estate", "estate", {"name": "Str", "flag": "Bool"})
sec_ast.register_collection(EST)


# -- isolation ----------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate():
    """Keep the module-level registries from leaking across tests."""
    saved_extractors = dict(sec_rules.EXTRACTORS)
    sec_rules.RULES.clear()
    sec_rules._LAST_WITNESS.clear()
    yield
    sec_rules.RULES.clear()
    sec_rules._LAST_WITNESS.clear()
    sec_rules.EXTRACTORS.clear()
    sec_rules.EXTRACTORS.update(saved_extractors)


# -- AST builders -------------------------------------------------------------

def fld(name, var="b"):
    return {"node": "field", "var": var, "field": name}


def lit(sort, value):
    return {"node": "lit", "sort": sort, "value": value}


def cmp(op, left, right):
    return {"node": "cmp", "op": op, "left": left, "right": right}


def exists(body, var="b", coll="iam_bindings"):
    return {"node": "exists", "var": var, "collection": coll, "body": body}


def forall(body, var="b", coll="iam_bindings"):
    return {"node": "forall", "var": var, "collection": coll, "body": body}


def owner_to_all_users(var="b"):
    """The bad property: this binding grants roles/owner to allUsers."""
    return {"node": "and", "args": [
        cmp("eq", fld("role", var), lit("Str", "roles/owner")),
        cmp("eq", fld("member", var), lit("Str", "allUsers")),
    ]}


#: refute: NO binding grants roles/owner to allUsers.
AST_OWNER = exists(owner_to_all_users())
#: assert_satisfiable-friendly forall body.
AST_VIEWER = forall(cmp("eq", fld("role"), lit("Str", "roles/viewer")))
AST_VIEWER_EXISTS = exists(cmp("eq", fld("role"), lit("Str", "roles/viewer")))

#: pair-tier AST: references both new and old bindings.
AST_PAIR = {"node": "and", "args": [
    exists(cmp("eq", fld("member", "n"), lit("Str", "allUsers")),
           var="n", coll="new_iam_bindings"),
    exists(cmp("eq", fld("member", "o"), lit("Str", "allUsers")),
           var="o", coll="old_iam_bindings"),
]}

#: estate-tier AST over the synthetic collection.
AST_EST = forall(cmp("eq", fld("name", "e"), lit("Str", "ok")), var="e", coll="syn_estate")


# -- Promise builders ---------------------------------------------------------

def _source():
    return sec_artifact.Source(file="req.md", line=7, text="a security requirement")


def placeholder_promise(pid, mode, ast, *, domain="iam", state="proposal",
                        sexpr="(assert true)", positive=None, negative=None):
    """A structurally-valid compiled Promise with placeholder sexpr/witnesses.

    Enough for :meth:`CompiledRule.evaluate` (which never reads them) and for
    duplicate / builtin-backend loader paths (which refuse before or skip the
    integrity checks)."""
    return sec_artifact.Promise(
        id=pid, source=_source(), domain=domain, mode=mode, state=state,
        severity="high", vocabulary=(), ast=ast, sexpr=sexpr, free_consts=(),
        positive=sec_artifact.Witness(assignment=positive or {ROLE_KEY: "x"},
                                      origin="pinned"),
        negative=sec_artifact.Witness(assignment=negative or {ROLE_KEY: "y"},
                                      origin="pinned"),
        wellformedness=sec_artifact.Wellformedness(satisfiable=True, non_tautological=True),
        status="compiled", reason="")


def minted_promise(pid, mode, ast, *, domain="iam", state="proposal"):
    """A compiled Promise whose witnesses come from real z3 models and whose
    ``sexpr`` is the ONE committed rendering — the clean, freshly-compiled
    artifact the integrity checks must accept.

    Re-pinned to :func:`sec_ast.render_sexpr`: that is the z3-independent form
    ``compile-requirements`` writes and the only one admission accepts. It was
    previously ``formula.sexpr()``, a rendering stage 1 never commits."""
    formula, consts = sec_encode.symbolic(Z3, ast)
    sexpr = sec_ast.render_sexpr(ast)
    obl = sec_probes.obligation(Z3, formula, mode)
    positive, negative = sec_probes.mint(Z3, obl, consts)
    assert positive is not None and negative is not None, "witnesses must mint"
    return sec_artifact.Promise(
        id=pid, source=_source(), domain=domain, mode=mode, state=state,
        severity="high", vocabulary=(), ast=ast, sexpr=sexpr,
        free_consts=tuple(sec_ast.free_consts(ast)),
        positive=sec_artifact.Witness(assignment=positive, origin="z3-model"),
        negative=sec_artifact.Witness(assignment=negative, origin="z3-model"),
        wellformedness=sec_artifact.Wellformedness(satisfiable=True, non_tautological=True),
        status="compiled", reason="")


def rule(promise):
    return sec_rules.CompiledRule(promise=promise)


def ctx(document=None, kind=None, *, baseline=None, solver=None, estate=None):
    return sec_rules.RuleContext(snapshot=SNAP, document=document, document_kind=kind,
                                 baseline=baseline, solver=solver, estate=estate)


_POLICIES = Path(__file__).parent / "fixtures" / "gcp" / "policies"
IAM_GOOD = json.loads((_POLICIES / "iam_policy_good.json").read_text())
IAM_ALLUSERS = {"bindings": [{"role": "roles/owner", "members": ["allUsers"]}]}
ORG_GOOD = json.loads((_POLICIES / "org_policy_good.json").read_text())
ORG_CONSTRAINT = "iam.disableServiceAccountKeyCreation"


# =============================================================================
# extractor / evaluation
# =============================================================================

def test_refute_rule_grounded_on_good_and_contradicted_on_allusers():
    r = rule(placeholder_promise("no-owner-allusers", "refute", AST_OWNER))
    good = ctx(IAM_GOOD, "iam_policy")
    bad = ctx(IAM_ALLUSERS, "iam_policy")
    if not HAVE_Z3:
        assert r.evaluate(good).status == "unverified"
        assert r.evaluate(bad).status == "unverified"
        return
    v_good = r.evaluate(good)
    assert v_good.status == "grounded" and v_good.kind == "sec:iam"
    v_bad = r.evaluate(bad)
    assert v_bad.status == "contradicted"
    # the witness names the violating binding
    assert "roles/owner" in v_bad.message and "allUsers" in v_bad.message
    stored = sec_rules.last_witness("no-owner-allusers")
    assert stored["collection"] == "iam_bindings"
    assert stored["record"]["role"] == "roles/owner"


def test_polarity_mirror_flips_the_buckets():
    """The same AST under assert_satisfiable yields the opposite verdict — the
    anti-inversion regression."""
    if not HAVE_Z3:
        return
    refute = rule(placeholder_promise("p-ref", "refute", AST_OWNER))
    asserts = rule(placeholder_promise("p-asr", "assert_satisfiable", AST_OWNER))
    good = ctx(IAM_GOOD, "iam_policy")
    bad = ctx(IAM_ALLUSERS, "iam_policy")
    assert refute.evaluate(good).status == "grounded"
    assert asserts.evaluate(good).status == "contradicted"
    assert refute.evaluate(bad).status == "contradicted"
    assert asserts.evaluate(bad).status == "grounded"


def test_empty_bindings_forall_grounded_exists_contradicted():
    empty = ctx({"bindings": []}, "iam_policy")
    forall_rule = rule(placeholder_promise("f", "assert_satisfiable", AST_VIEWER))
    exists_rule = rule(placeholder_promise("e", "assert_satisfiable", AST_VIEWER_EXISTS))
    if not HAVE_Z3:
        assert forall_rule.evaluate(empty).status == "unverified"
        return
    assert forall_rule.evaluate(empty).status == "grounded"      # empty-forall is True
    assert exists_rule.evaluate(empty).status == "contradicted"  # empty-exists is False


def test_pair_tier_missing_baseline_then_decided():
    r = rule(placeholder_promise("pair", "refute", AST_PAIR, state="pair"))
    no_base = r.evaluate(ctx(IAM_GOOD, "iam_policy", baseline=None))
    assert no_base.status == "unverified"
    assert "no baseline document was given" in no_base.message

    with_base = r.evaluate(ctx(IAM_GOOD, "iam_policy", baseline=IAM_GOOD))
    if not HAVE_Z3:
        assert with_base.status == "unverified"
        assert "z3 is not available" in with_base.message
        return
    assert with_base.status in ("grounded", "contradicted")


def test_estate_tier_names_uncaptured_collection():
    r = rule(placeholder_promise("est", "assert_satisfiable", AST_EST, state="estate"))
    v = r.evaluate(ctx(None, None))  # no extractor registered for syn_estate
    assert v.status == "unverified"
    assert "syn_estate" in v.message
    assert "the estate-tier rule was not evaluated" in v.message


def test_unrecognized_binding_key_is_unverified_never_contradicted():
    typo = {"bindings": [{"role": "roles/owner", "member": "allUsers"}]}  # member vs members
    r = rule(placeholder_promise("typo", "refute", AST_OWNER))
    v = r.evaluate(ctx(typo, "iam_policy"))
    assert v.status == "unverified"
    assert v.status != "contradicted"
    assert "'member'" in v.message


def test_no_z3_every_rule_is_unverified():
    r = rule(placeholder_promise("nz", "refute", AST_OWNER))
    v = r.evaluate(ctx(IAM_GOOD, "iam_policy", solver=get_solver("builtin")))
    assert v.status == "unverified"
    assert "z3 is not available" in v.message


def test_register_extractor_makes_estate_collection_evaluable():
    records = ({"name": "ok", "flag": True},)
    sec_rules.register_extractor("syn_estate", lambda c: (records, None))
    r = rule(placeholder_promise("est2", "assert_satisfiable", AST_EST, state="estate"))
    assert r.missing_inputs(ctx(None, None)) == ()
    v = r.evaluate(ctx(None, None))
    if not HAVE_Z3:
        assert v.status == "unverified" and "z3 is not available" in v.message
        return
    assert v.status == "grounded"


# =============================================================================
# the org-policy extractor's kind guard (MK-S02)
# =============================================================================

def test_org_policy_rules_requires_the_org_policy_kind_in_both_directions():
    """The kind guard, pinned in BOTH directions — one direction cannot tell a
    guard from its own inversion.

    An ``org_policy`` context carrying a well-formed policy must yield RECORDS
    and no reason; a context of any OTHER kind must yield the refusal pair. The
    non-org_policy contexts here deliberately carry a NON-``None`` document,
    because ``ctx.document is None`` refuses on its own and would answer the
    guard and its inverse alike — a refusal obtained that way pins nothing.
    """
    records, reason = sec_rules.org_policy_rules(ctx(ORG_GOOD, "org_policy"))
    assert reason is None
    assert records == ({"constraint": ORG_CONSTRAINT, "is_list": False,
                        "enforce": True, "value": ""},)

    listed = {"name": f"projects/p/policies/{ORG_CONSTRAINT}",
              "spec": {"rules": [{"enforce": True,
                                  "values": {"allowedValues": ["b", "a"]}}]}}
    records, reason = sec_rules.org_policy_rules(ctx(listed, "org_policy"))
    assert reason is None
    assert [r["value"] for r in records] == ["a", "b"]
    assert all(r["is_list"] and r["constraint"] == ORG_CONSTRAINT for r in records)

    refusal = ((), "the document under review is not an Org Policy")
    for kind in ("iam_policy", "firewall_rule", "tf_plan", "security_policy", None):
        assert sec_rules.org_policy_rules(ctx(ORG_GOOD, kind)) == refusal, kind

    # the guard's second disjunct: the right kind with nothing to read.
    assert sec_rules.org_policy_rules(ctx(None, "org_policy")) == refusal


# =============================================================================
# the admitted-rule record (MK-S01)
# =============================================================================

def test_compiled_rule_is_frozen_and_hashable():
    """An admitted rule is IMMUTABLE, and its type participates in hashing.

    ``frozen=False`` would silently let a compiled rule be REWRITTEN AFTER
    ADMISSION — the artifact-tier version of the widening this task reverses —
    and would set the type's ``__hash__`` to ``None``.
    """
    r = rule(placeholder_promise("frozen-pin", "refute", AST_OWNER))
    swapped = placeholder_promise("swapped", "refute", AST_VIEWER_EXISTS)

    with pytest.raises(dataclasses.FrozenInstanceError):
        r.promise = swapped
    assert r.promise.id == "frozen-pin"      # admission survived the attempt

    # HASHING. The frozen record's generated ``__hash__`` DELEGATES to its one
    # field, and that field's ast is a plain dict, so the rule cannot really
    # enter a dict or a set here (ESC-GX-SEXPR-001, and the strict-xfailed
    # spec-literal below). What is observable — and what an unfrozen rule
    # changes — is WHICH type refuses: the dict inside the promise, never the
    # rule type itself, whose ``__hash__`` would be ``None``.
    with pytest.raises(TypeError, match="unhashable type: 'dict'"):
        {r: "admitted"}
    with pytest.raises(TypeError, match="unhashable type: 'dict'"):
        {r}


@pytest.mark.xfail(strict=True, reason="ESC-GX-SEXPR-001: Promise carries its ast as a plain dict")
def test_compiled_rule_instance_is_usable_as_a_dict_key():
    """SPEC-LITERAL under house rule 4, for the half of MK-S01's killing-test
    clause this task's declared path cannot satisfy: "the same instance works as
    a dict key and a set member". It does not, on CLEAN source, because
    ``sec_artifact.Promise`` stores the ast as a plain ``dict`` — see
    ESC-GX-SEXPR-001 for what would close it. Landed strict, so the day
    ``Promise`` grows a hashable ast this XPASSes and says so."""
    r = rule(placeholder_promise("hash-pin", "refute", AST_OWNER))
    assert {r: "admitted"}[r] == "admitted"
    assert len({r, r}) == 1


# =============================================================================
# applicability (the abstain-flood guard)
# =============================================================================

def test_iam_rule_not_applicable_to_firewall_document_adds_nothing():
    r = rule(placeholder_promise("a", "refute", AST_OWNER))
    report = []
    v = r.evaluate(ctx(IAM_GOOD, "firewall_rule"))
    assert v is None
    if v is not None:
        report.append(v)
    assert report == []          # empty verdict list, NOT an unverified
    assert r.applies_to(ctx(IAM_GOOD, "firewall_rule")) is False


def test_iam_rule_applicable_to_iam_and_tf_plan():
    r = rule(placeholder_promise("b", "refute", AST_OWNER))
    assert r.applies_to(ctx(IAM_GOOD, "iam_policy")) is True
    # a plan can carry IAM resources, so it is applicable
    assert r.applies_to(ctx(IAM_GOOD, "tf_plan")) is True
    decided = r.evaluate(ctx(IAM_GOOD, "iam_policy"))
    assert decided is not None
    if HAVE_Z3:
        assert decided.status == "grounded"


def test_unknown_document_kind_is_applicable_and_emits_unverified():
    """The fail-loud default: an unrecognized/None kind stays applicable so a
    rule that should have run never vanishes."""
    r = rule(placeholder_promise("c", "refute", AST_OWNER))
    assert r.applies_to(ctx(IAM_GOOD, None)) is True
    v = r.evaluate(ctx(IAM_GOOD, None))
    assert v is not None
    assert v.status == "unverified"


# =============================================================================
# loader / carry verdicts / duplicates
# =============================================================================

def _write(tmp_path, name, doc):
    path = tmp_path / name
    sec_artifact.atomic_write(str(path), sec_artifact.dumps(doc))
    return str(path)


def _doc(promises, source_doc="art.json"):
    return sec_artifact.PromiseDoc(source_doc=source_doc, promises=tuple(promises))


def _rejected(pid):
    return sec_artifact.Promise(id=pid, source=_source(), domain="iam",
                                mode="refute", state="proposal", severity="high",
                                status="rejected", reason="ast failed to encode")


def _unverified(pid):
    return sec_artifact.Promise(id=pid, source=_source(), domain="iam",
                                mode="refute", state="proposal", severity="high",
                                status="unverified", reason="vocabulary did not ground")


def _compiled_for_backend(pid, mode, ast):
    return minted_promise(pid, mode, ast) if HAVE_Z3 else placeholder_promise(pid, mode, ast)


def test_load_directory_registers_only_compiled_and_carries_the_rest(tmp_path):
    _write(tmp_path, "a.promises.json", _doc([_compiled_for_backend("keep", "refute", AST_OWNER)],
                                             source_doc="a.json"))
    _write(tmp_path, "b.promises.json", _doc([_rejected("drop-rej")], source_doc="b.json"))
    _write(tmp_path, "c.promises.json", _doc([_unverified("drop-unv")], source_doc="c.json"))

    rules, verdicts = sec_rules.load_directory(str(tmp_path))

    assert {r.promise.id for r in rules} == {"keep"}
    assert set(sec_rules.RULES) == {"keep"}
    # carry verdicts re-emitted for the non-compiled promises
    rej = [v for v in verdicts if v.target == "drop-rej"]
    assert len(rej) == 1 and rej[0].status == "unverified"
    assert "rejected at compile time" in rej[0].message and "did not run" in rej[0].message
    unv = [v for v in verdicts if v.target == "drop-unv"]
    assert len(unv) == 1 and unv[0].status == "unverified"


def test_duplicate_id_across_artifacts_refuses_both(tmp_path):
    d1 = _doc([placeholder_promise("dup", "refute", AST_OWNER)], source_doc="fileA.json")
    d2 = _doc([placeholder_promise("dup", "refute", AST_OWNER)], source_doc="fileB.json")
    rules, verdicts = sec_rules.load_rules([d1, d2])

    art = [v for v in verdicts if v.kind == "sec:artifact"]
    assert len(art) == 1
    assert art[0].status == "contradicted" and art[0].target == "dup"
    assert "fileA.json" in art[0].message and "fileB.json" in art[0].message
    assert "dup" not in sec_rules.RULES
    assert rules == ()


def test_bad_artifact_yields_one_unverified_while_others_load(tmp_path):
    good_path = _write(tmp_path, "g.promises.json",
                       _doc([_compiled_for_backend("ok", "refute", AST_OWNER)], source_doc="g.json"))
    bad_path = str(tmp_path / "bad.promises.json")
    with open(bad_path, "w") as fh:
        fh.write("{ this is not json ]")

    rules, verdicts = sec_rules.load_rules([bad_path, good_path])
    load_fail = [v for v in verdicts if v.kind == "sec:artifact" and bad_path in v.target]
    assert len(load_fail) == 1 and load_fail[0].status == "unverified"
    assert {r.promise.id for r in rules} == {"ok"}


def test_by_state_and_by_domain(tmp_path):
    _write(tmp_path, "a.promises.json",
           _doc([_compiled_for_backend("only", "refute", AST_OWNER)], source_doc="a.json"))
    rules, _ = sec_rules.load_directory(str(tmp_path))
    ids = {r.promise.id for r in rules}
    assert {r.promise.id for r in sec_rules.by_domain("iam")} >= ids
    assert {r.promise.id for r in sec_rules.by_state("proposal")} >= ids
    assert sec_rules.by_domain("cloud_armor") == ()


# =============================================================================
# admission integrity (the anti-tamper pins)
# =============================================================================

def _load_mutated(tmp_path, name, mutate):
    """Build a clean minted doc, mutate one JSON field, reload it (HAVE_Z3)."""
    doc = _doc([minted_promise("pin", "refute", AST_OWNER)], source_doc=f"{name}.json")
    data = json.loads(sec_artifact.dumps(doc))
    mutate(data)
    path = tmp_path / f"{name}.promises.json"
    path.write_text(json.dumps(data))
    return sec_rules.load_rules([str(path)], solver=_SOLVER)


def test_clean_artifact_passes_both_checks(tmp_path):
    if not HAVE_Z3:
        return
    rules, verdicts = _load_mutated(tmp_path, "clean", lambda d: None)
    assert {r.promise.id for r in rules} == {"pin"}
    assert [v for v in verdicts if v.kind == "sec:artifact"] == []


def test_flipped_mode_is_refused_by_witness_reclassification(tmp_path):
    if not HAVE_Z3:
        return
    def flip(data):
        data["promises"][0]["mode"] = "assert_satisfiable"
    rules, verdicts = _load_mutated(tmp_path, "flip", flip)
    art = [v for v in verdicts if v.kind == "sec:artifact"]
    assert rules == ()
    assert len(art) == 1 and art[0].status == "contradicted" and art[0].target == "pin"
    assert "witness no longer classifies" in art[0].message


def _load_with_sexpr(tmp_path, name, sexpr):
    """A clean minted artifact whose stored ``sexpr`` is replaced by *sexpr*
    verbatim, then loaded — so a test can choose the rendering under test rather
    than inherit whichever one :func:`minted_promise` happens to store."""
    return _load_mutated(
        tmp_path, name,
        lambda data: data["promises"][0]["smt"].__setitem__("sexpr", sexpr))


def test_the_committed_sexpr_has_exactly_one_renderer(tmp_path):
    """ONE strict form, and the guard REJECTS the other one.

    ``sec_ast.render_sexpr`` is the artifact's committed, z3-independent
    rendering. Encoding the SAME ast through z3 gives a different string, and an
    artifact carrying THAT string is not a differently-spelled clean artifact —
    it is an artifact whose stored rendering disagrees with the one renderer, and
    admission must refuse it. A guard that accepts either form admits both and
    this pin goes red, which is exactly what it is here to catch.
    """
    if not HAVE_Z3:
        # Without z3 admission abstains before the comparison, so the strict form
        # is not consulted; the documented builtin behaviour is that the artifact
        # still registers carrying an honest integrity note.
        path = _write(tmp_path, "one.promises.json",
                      _doc([placeholder_promise("pin", "refute", AST_OWNER,
                                                sexpr=sec_ast.render_sexpr(AST_OWNER))],
                           source_doc="one.json"))
        rules, verdicts = sec_rules.load_rules([path], solver=_SOLVER)
        assert {r.promise.id for r in rules} == {"pin"}
        note = [v for v in verdicts if v.kind == "sec:artifact"]
        assert len(note) == 1 and note[0].status == "unverified"
        return

    one_form = sec_ast.render_sexpr(AST_OWNER)
    z3_form = sec_encode.symbolic(Z3, AST_OWNER)[0].sexpr()
    # Non-vacuity: the two renderers must really disagree, or "rejects the other
    # form" would be satisfied by rejecting nothing.
    assert one_form != z3_form

    rules, verdicts = _load_with_sexpr(tmp_path, "one-form", one_form)
    assert {r.promise.id for r in rules} == {"pin"}
    assert [v for v in verdicts if v.kind == "sec:artifact"] == []

    rules, verdicts = _load_with_sexpr(tmp_path, "other-form", z3_form)
    art = [v for v in verdicts if v.kind == "sec:artifact"]
    assert rules == ()
    assert len(art) == 1 and art[0].status == "contradicted"
    assert "does not match a fresh encoding" in art[0].message


def test_weakened_ast_is_refused_by_sexpr_mismatch(tmp_path):
    """REGRESSION PIN. Hand-editing the ast while leaving the stored rendering
    intact is ``contradicted sec:artifact``, naming the mismatch.

    This one passed under the two-form guard too — the ast moves, so every
    rendering of it moves — so it is evidence of nothing about the widening. It
    is here to stay red if the comparison is ever dropped. Its non-vacuity is
    asserted, not assumed: the edit must really move the one form, or "refused on
    mismatch" would hold with no mismatch to refuse."""
    weakened = exists({"node": "and", "args": [
        cmp("ne", fld("role"), lit("Str", "roles/owner")),
        cmp("eq", fld("member"), lit("Str", "allUsers")),
    ]})
    assert sec_ast.render_sexpr(weakened) != sec_ast.render_sexpr(AST_OWNER)

    if not HAVE_Z3:
        # Builtin backend: the comparison is not reached, and the documented
        # behaviour is a registered rule carrying an honest integrity note —
        # never a silent clean load.
        path = _write(tmp_path, "weak.promises.json",
                      _doc([placeholder_promise("pin", "refute", weakened,
                                                sexpr=sec_ast.render_sexpr(AST_OWNER))],
                           source_doc="weak.json"))
        rules, verdicts = sec_rules.load_rules([path], solver=_SOLVER)
        assert {r.promise.id for r in rules} == {"pin"}
        note = [v for v in verdicts if v.kind == "sec:artifact"]
        assert len(note) == 1 and note[0].status == "unverified"
        return

    def weaken(data):
        # relax the role equality (cmp eq -> cmp ne) but leave the stored sexpr
        args = data["promises"][0]["smt"]["ast"]["body"]["args"]
        args[0]["op"] = "ne"
    rules, verdicts = _load_mutated(tmp_path, "weak", weaken)
    art = [v for v in verdicts if v.kind == "sec:artifact"]
    assert rules == ()
    assert len(art) == 1 and art[0].status == "contradicted"
    assert "does not match a fresh encoding" in art[0].message


def test_edited_witness_is_refused(tmp_path):
    if not HAVE_Z3:
        return
    def edit(data):
        data["promises"][0]["witnesses"]["positive"]["assignment"] = {
            ROLE_KEY: "roles/owner", MEMBER_KEY: "allUsers"}
    rules, verdicts = _load_mutated(tmp_path, "wit", edit)
    art = [v for v in verdicts if v.kind == "sec:artifact"]
    assert rules == ()
    assert len(art) == 1 and art[0].status == "contradicted"
    assert "witness no longer classifies" in art[0].message


def test_no_z3_tampered_artifact_registers_with_note(tmp_path):
    """Without z3 a tampered artifact is never a silent clean load: it registers
    but carries an unverified sec:artifact note saying integrity was not verified."""
    doc = _doc([placeholder_promise("nzp", "refute", AST_OWNER, sexpr="(assert tampered)")],
               source_doc="nz.json")
    path = _write(tmp_path, "nz.promises.json", doc)
    rules, verdicts = sec_rules.load_rules([path], solver=get_solver("builtin"))
    assert {r.promise.id for r in rules} == {"nzp"}
    note = [v for v in verdicts if v.kind == "sec:artifact" and v.target == "nzp"]
    assert len(note) == 1 and note[0].status == "unverified"
    assert "integrity" in note[0].message
