"""Stage-1 compiler tests (:mod:`gcp_grounding.sec_compile`).

These use the ``HAVE_Z3`` branch idiom of the encode/probe suites: rather than
*skip* the z3-dependent cases on the builtin backend, each test BRANCHES. Under
the oracle (z3 present) the real ``compiled``/``rejected`` assertions run; on the
builtin backend the same test asserts the honest abstention (``unverified``,
never a false pass) that the pipeline must produce when z3 is absent.

The golden artifact ``fixtures/gcp/sec/expected/iam.promises.json`` was generated
by compiling ``fixtures/gcp/sec/iam.md`` against ``fixtures/gcp/snapshot.json``
and committed verbatim. It is compared field-by-field EXCEPT the two witness
assignment maps, which are compared for key-set equality and re-classified live —
z3 models are not version-stable, but classification is, so a z3 upgrade must not
turn this suite red.

Every test writes only into ``tmp_path``; the repo's real
``sec_requirements/compiled/`` is never created.
"""

import json
import shutil
from pathlib import Path

import pytest

from gcp_grounding import sec_artifact, sec_compile, sec_probes
from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
SEC = FIXTURES / "sec"
GOLDEN = SEC / "expected" / "iam.promises.json"

_SOLVER = get_solver()
Z3 = _z3_module(_SOLVER)
HAVE_Z3 = _SOLVER.backend == "z3"

IAM_IDS = {"no-public-principals", "no-primitive-owner", "bindings-are-conditioned"}


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


def _by_id(doc):
    return {p.id: p for p in doc.promises}


# -- iam.md: the clean, three-promise document --------------------------------

def test_iam_compiles_three_promises(snap, tmp_path):
    res = sec_compile.compile_document(SEC / "iam.md", snap, out_dir=tmp_path)
    assert {p.id for p in res.doc.promises} == IAM_IDS
    assert Path(res.written).exists()
    if HAVE_Z3:
        assert all(p.status == "compiled" for p in res.doc.promises), \
            [(p.id, p.status, p.reason) for p in res.doc.promises]
        for p in res.doc.promises:
            assert p.positive is not None and p.negative is not None
        assert res.report.ok
    else:
        # No z3: honest abstention, and ignorance never fails the gate.
        assert all(p.status == "unverified" for p in res.doc.promises)
        assert res.report.ok


def test_recompile_is_byte_identical(snap, tmp_path):
    # Same out_dir twice: the second compile reads the first as its prior and
    # reuses the pinned witnesses, so the bytes must be identical.
    first = sec_compile.compile_document(SEC / "iam.md", snap, out_dir=tmp_path)
    text1 = Path(first.written).read_text(encoding="utf-8")
    second = sec_compile.compile_document(SEC / "iam.md", snap, out_dir=tmp_path)
    text2 = Path(second.written).read_text(encoding="utf-8")
    assert text1 == text2


# -- the committed golden artifact --------------------------------------------

def test_check_only_golden_reports_no_drift(snap, tmp_path):
    committed = tmp_path / "iam.promises.json"
    shutil.copy(GOLDEN, committed)
    res = sec_compile.compile_document(SEC / "iam.md", snap, out_dir=tmp_path,
                                       check_only=True)
    assert res.written == ""
    if HAVE_Z3:
        assert res.drifted is False
        assert not any(v.kind == "sec:artifact" for v in res.report.verdicts)
        # check_only never writes.
        assert committed.read_text(encoding="utf-8") == GOLDEN.read_text(encoding="utf-8")
    else:
        # A builtin fresh compile is all-unverified, so it genuinely differs from
        # the committed compiled artifact — an honest drift, not a false pass.
        assert res.drifted is True


def test_golden_field_by_field(snap, tmp_path):
    golden = sec_artifact.load(GOLDEN)
    res = sec_compile.compile_document(SEC / "iam.md", snap, out_dir=tmp_path)
    fresh = res.doc
    assert {p.id for p in fresh.promises} == {p.id for p in golden.promises}
    assert fresh.schema == golden.schema
    assert fresh.source_doc == golden.source_doc
    assert fresh.source_sha256 == golden.source_sha256
    assert fresh.snapshot_captured_at == golden.snapshot_captured_at
    assert fresh.encoder == golden.encoder

    gmap, fmap = _by_id(golden), _by_id(fresh)
    if not HAVE_Z3:
        assert all(p.status == "unverified" for p in fresh.promises)
        return

    for pid, g in gmap.items():
        f = fmap[pid]
        # Every field except the witness assignment values.
        assert f.source == g.source
        assert (f.domain, f.mode, f.state, f.severity) == \
               (g.domain, g.mode, g.state, g.severity)
        assert f.ast == g.ast
        assert f.sexpr == g.sexpr
        assert f.free_consts == g.free_consts
        assert f.vocabulary == g.vocabulary
        assert f.wellformedness == g.wellformedness
        assert (f.status, f.reason) == (g.status, g.reason)
        assert f.notes == g.notes
        assert f.vocabulary_unverified == g.vocabulary_unverified
        # Witnesses: key-set equality, then re-classify the pinned ones live.
        assert set(f.positive.assignment) == set(g.positive.assignment)
        assert set(f.negative.assignment) == set(g.negative.assignment)
        positive_ok, negative_ok = sec_probes.reclassify(Z3, g)
        assert positive_ok is True and negative_ok is True


def test_mutated_witness_recompiles_as_drift(snap, tmp_path):
    data = json.loads(GOLDEN.read_text(encoding="utf-8"))
    for promise in data["promises"]:
        if promise["id"] == "no-public-principals":
            # Flip the negative (violating) witness to a compliant value.
            promise["witnesses"]["negative"]["assignment"] = {
                "iam_bindings#b.member": "user:not-public-anymore@acme.example"}
    (tmp_path / "iam.promises.json").write_text(json.dumps(data), encoding="utf-8")

    res = sec_compile.compile_document(SEC / "iam.md", snap, out_dir=tmp_path)
    promise = _by_id(res.doc)["no-public-principals"]
    if HAVE_Z3:
        assert promise.status == "rejected"
        assert "drift" in promise.reason
        assert res.report.ok is False
    else:
        # No z3: the reuse/re-classification path is unreachable, so it abstains.
        assert promise.status == "unverified"


# -- degenerate.md: one fixture per abstain / rejection path ------------------

def test_degenerate_every_failure_mode(snap, tmp_path):
    res = sec_compile.compile_document(SEC / "degenerate.md", snap, out_dir=tmp_path)
    by = _by_id(res.doc)
    verdicts = res.report.verdicts

    # -- z3-independent outcomes (true on both backends) --
    # Hallucinated role: rejected by the Datalog vocabulary grounder.
    assert by["hallucinated-role"].status == "rejected"
    assert "not grounded" in by["hallucinated-role"].reason
    ungrounded = [v for v in verdicts
                  if v.status == "ungrounded" and "roles/bigquery.reader" in v.target]
    assert ungrounded, "expected an ungrounded vocabulary verdict"
    assert any("roles/bigquery.dataViewer" in v.suggestions for v in ungrounded)

    # Unregistered collection: the parser could not resolve it -> unverified.
    assert by["unregistered-collection"].status == "unverified"

    # Untranslated section: no promise block -> unverified, sentence quoted.
    untranslated = [p for p in res.doc.promises if p.id.startswith("untranslated-")]
    assert len(untranslated) == 1
    upromise = untranslated[0]
    assert upromise.status == "unverified"
    umsg = [v.message for v in verdicts
            if v.kind == "sec:compile" and v.target == upromise.id]
    assert umsg and repr(upromise.source.text) in umsg[0]
    assert "Access reviews" in upromise.source.text

    # cel: unverified on both backends (the encoder refuses it, or z3 is absent).
    assert by["cel-bearing-promise"].status == "unverified"

    assert res.report.ok is False

    # -- z3-gated outcomes --
    if HAVE_Z3:
        assert by["unsatisfiable-promise"].status == "rejected"
        assert "unsatisfiable" in by["unsatisfiable-promise"].reason
        assert by["tautological-promise"].status == "rejected"
        assert "tautology" in by["tautological-promise"].reason
        assert "cel" in by["cel-bearing-promise"].reason
        rejected = {p.id for p in res.doc.promises if p.status == "rejected"}
        assert rejected == {"unsatisfiable-promise", "tautological-promise",
                            "hallucinated-role"}
        unverified = {p.id for p in res.doc.promises if p.status == "unverified"}
        assert unverified == {"unregistered-collection", "cel-bearing-promise",
                              upromise.id}
    else:
        assert by["unsatisfiable-promise"].status == "unverified"
        assert by["tautological-promise"].status == "unverified"


def test_degenerate_is_idempotent(snap, tmp_path):
    # Two independent output directories (no reuse): the whole corpus, cel and
    # all, must compile byte-identically. cel-bearing-promise is the pin — it
    # mints nothing (sec_encode refuses cel), so it can never flip status.
    one = sec_compile.compile_document(SEC / "degenerate.md", snap,
                                       out_dir=tmp_path / "one")
    two = sec_compile.compile_document(SEC / "degenerate.md", snap,
                                       out_dir=tmp_path / "two")
    text1 = Path(one.written).read_text(encoding="utf-8")
    text2 = Path(two.written).read_text(encoding="utf-8")
    assert text1 == text2, (
        "degenerate.md did not compile idempotently; the usual culprit is "
        "cel-bearing-promise minting a witness on the first run but failing to "
        "re-classify it on the second — sec_encode must refuse cel outright")


# -- state cross-check --------------------------------------------------------

_MISMATCH_MD = (
    "---\n"
    "domain: iam\n"
    "---\n"
    "\n"
    "## Mismatched state\n"
    "\n"
    "A binding must not grant the owner role.\n"
    "\n"
    "```promise\n"
    "id: state-mismatch\n"
    "mode: refute\n"
    "state: estate\n"
    "smt:\n"
    "  exists b in iam_bindings\n"
    '    cmp eq field b.role str "roles/owner"\n'
    "```\n"
)


def test_declared_derived_state_mismatch_rejects(snap, tmp_path):
    md = tmp_path / "mismatch.md"
    md.write_text(_MISMATCH_MD, encoding="utf-8")
    res = sec_compile.compile_document(md, snap, out_dir=tmp_path)
    promise = _by_id(res.doc)["state-mismatch"]
    # The state cross-check runs before z3, so it rejects on any backend.
    assert promise.status == "rejected"
    assert "declared state 'estate'" in promise.reason
    assert "proposal" in promise.reason
    assert res.report.ok is False


# -- orgpolicy.md: a pair-tier promise ----------------------------------------

def test_orgpolicy_pair_promise(snap, tmp_path):
    res = sec_compile.compile_document(SEC / "orgpolicy.md", snap, out_dir=tmp_path)
    promise = _by_id(res.doc)["no-new-owner-grants"]
    assert promise.state == "pair"
    if HAVE_Z3:
        assert promise.status == "compiled"
    else:
        assert promise.status == "unverified"


# -- an explicitly builtin backend --------------------------------------------

def test_no_z3_abstains_every_promise(snap, tmp_path):
    builtin = get_solver("builtin")
    res = sec_compile.compile_document(SEC / "iam.md", snap, out_dir=tmp_path,
                                       solver=builtin)
    assert all(p.status == "unverified" for p in res.doc.promises)
    assert all("z3 is not available" in p.reason for p in res.doc.promises)
    # Ignorance never fails: the command still exits 0.
    assert res.report.ok is True


# -- the directory driver -----------------------------------------------------

def test_compile_directory_sorted_and_missing(snap, tmp_path):
    results = sec_compile.compile_directory(SEC, snap, out_dir=tmp_path)
    assert len(results) == 3
    docs = [r.doc.source_doc for r in results]
    assert docs == sorted(docs)
    assert all(r.written for r in results)

    # A missing directory yields an empty tuple, never raising.
    missing = sec_compile.compile_directory(tmp_path / "nope", snap, out_dir=tmp_path)
    assert missing == ()
