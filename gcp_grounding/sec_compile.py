"""Stage 1 of the ``sec_requirements/`` compiler: parse, ground, probe, mint, write.

A security engineer drops a Markdown requirement document into a directory; this
module turns it into a reviewable, git-committed ``<stem>.promises.json`` artifact
— the review boundary that stage 2 (``sec_rules``) later compiles into z3 rules
running in the same dispatch. Everything here is deterministic and LLM-free.

The pipeline is a straight line per document (see :func:`compile_document`): the
Markdown front end (:mod:`sec_parse`) yields candidates; each candidate is
grounded against the snapshot vocabulary (:mod:`sec_vocab`), its declared state
is cross-checked against the collections it references (:mod:`sec_ast`), its AST
is symbolically encoded (:mod:`sec_encode`) and probed for well-formedness,
witnesses are minted — or reused and re-classified — (:mod:`sec_probes`), and the
whole set is checked for pairwise independence. The result is assembled into a
:class:`~gcp_grounding.sec_artifact.PromiseDoc` and either written atomically or,
in ``check_only`` mode, compared against the committed bytes.

HONESTY. Every abstain path lands in ``unverified`` and never fails the gate: a
:class:`~gcp_grounding.sec_parse.ParseError`, a candidate the parser could not
translate, an absent z3 backend, an :class:`~gcp_grounding.sec_encode.UnsupportedTerm`
(``cel`` is the canonical one), or a solver that gave up. Only a genuinely broken
requirement — unsatisfiable, tautological, ungrounded vocabulary, a declared/
derived state mismatch, witness drift, or a fatal forall/forall conflict —
``rejected`` and makes :attr:`report.ok` False.

IDEMPOTENCE. Compiling the same Markdown twice against the same snapshot produces
byte-identical artifacts. Witnesses are reused verbatim (and merely re-classified)
whenever a previous artifact carries a promise with the same id and a byte-
identical AST, so the committed witnesses stay stable across a z3 upgrade — z3
models are not version-stable, but classification is. The one way this property
breaks is a promise that mints on the first compile but cannot re-classify on the
next; that is exactly why :mod:`sec_encode` refuses ``cel`` outright, so a
cel-bearing promise is ``unverified`` deterministically on every run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import constraints, sec_artifact, sec_ast, sec_encode, sec_parse, sec_probes, sec_vocab
from .core.log import get_logger
from .core.report import GroundingReport, Verdict
from .core.solver import get_solver
from .knowledge import GcpSnapshot
from .sec_artifact import PromiseDoc

logger = get_logger(__name__)

__all__ = ["CompileResult", "compile_document", "compile_directory"]


# -- public result ------------------------------------------------------------

@dataclass(frozen=True)
class CompileResult:
    """The outcome of compiling one document.

    ``doc`` is the assembled :class:`PromiseDoc` (``None`` only when the file
    could not be parsed at all), ``report`` carries one status verdict per
    promise plus the vocabulary verdicts, ``written`` is the artifact path that
    was written (empty in ``check_only`` mode or on a parse failure) and
    ``drifted`` is True only in ``check_only`` mode when the committed bytes do
    not match a fresh compile.
    """

    doc: Optional[PromiseDoc]
    report: GroundingReport
    written: str
    drifted: bool


# -- the mutable per-promise accumulator --------------------------------------

class _Pending:
    """Scratch state for one candidate as it flows through the pipeline.

    Finalized into an immutable :class:`~gcp_grounding.sec_artifact.Promise` by
    :func:`_finalize`. ``status`` is ``None`` while the promise is still on the
    compiled track; a terminal ``rejected``/``unverified`` short-circuits the
    remaining steps.
    """

    def __init__(self, cand, source, domain, mode, severity, declared_state):
        self.id = cand.id
        self.source = source
        self.domain = domain
        self.mode = mode
        self.severity = severity
        self.declared_state = declared_state
        self.ast = cand.ast
        self.notes = tuple(cand.notes)
        self.vocabulary = tuple(sec_artifact.VocabRef(kind, value)
                                for kind, value in cand.vocab)
        self.vocabulary_unverified: tuple[str, ...] = ()
        self.derived: Optional[str] = None
        self.state: Optional[str] = None
        self.sexpr = ""
        self.free_consts: tuple[tuple[str, str], ...] = ()
        self.positive = None
        self.negative = None
        self.wf_satisfiable: Optional[bool] = None
        self.wf_non_tautological: Optional[bool] = None
        self.wf_independent: Optional[bool] = None
        self.wf_conflicts: tuple[str, ...] = ()
        self.wf_notes: tuple[str, ...] = ()
        self.status: Optional[str] = None
        self.reason = ""
        # z3 carry-overs for the independence probe (compiled track only).
        self.obligation = None
        self.forall_rooted = False
        self.collections: tuple[str, ...] = ()


# -- sexpr rendering ----------------------------------------------------------
#
# A deterministic, z3-INDEPENDENT s-expression rendering of the AST, stored in
# the artifact for human review. It is derived purely from the (already
# canonical) AST rather than from ``str(formula)`` so the committed bytes are
# stable across z3 versions — the same reason witnesses are re-classified rather
# than re-minted.

def _render_term(term) -> str:
    if term.get("node") == "field":
        return f"{term['var']}.{term['field']}"
    sort, value = term.get("sort"), term.get("value")
    if sort == "Str":
        return _quote(value)
    if sort == "Bool":
        return "true" if value else "false"
    return str(value)


def _quote(text: str) -> str:
    return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _render_sexpr(node) -> str:
    kind = node["node"]
    if kind in ("true", "false"):
        return kind
    if kind == "not":
        return f"(not {_render_sexpr(node['arg'])})"
    if kind in ("and", "or"):
        return f"({kind} " + " ".join(_render_sexpr(a) for a in node["args"]) + ")"
    if kind == "implies":
        return f"(=> {_render_sexpr(node['if'])} {_render_sexpr(node['then'])})"
    if kind in ("atmost", "atleast"):
        return (f"({kind} {node['k']} "
                + " ".join(_render_sexpr(a) for a in node["args"]) + ")")
    if kind in ("forall", "exists"):
        return (f"({kind} (({node['var']} {node['collection']})) "
                f"{_render_sexpr(node['body'])})")
    if kind == "cmp":
        return f"({node['op']} {_render_term(node['left'])} {_render_term(node['right'])})"
    if kind == "in":
        items = " ".join(_quote(x) for x in node["set"]["items"])
        return f"(in {_render_term(node['term'])} (set {items}))"
    if kind in ("prefix", "suffix", "contains"):
        return f"({kind} {_render_term(node['term'])} {_quote(node['value'])})"
    if kind == "cidr_contains":
        return f"(cidr_contains {_render_term(node['cidr'])} {_render_term(node['addr'])})"
    if kind == "port_in":
        return f"(port_in {_render_term(node['term'])} {node['lo']} {node['hi']})"
    if kind == "cel":
        return f"(cel {_quote(node['expr'])})"
    return f"({kind})"


# -- path helpers -------------------------------------------------------------

def _repo_root(start: Path) -> Optional[Path]:
    """The nearest ancestor of *start* carrying a ``pyproject.toml`` marker."""
    for parent in [start, *start.parents]:
        if (parent / "pyproject.toml").exists():
            return parent
    return None


def _repo_relative(path: Path) -> str:
    """*path* as a repo-relative POSIX string, so the artifact is checkout-stable.

    Falls back to a cwd-relative path when the file lives outside the repo (e.g.
    a ``tmp_path`` in a test), which is still deterministic within a run.
    """
    resolved = path.resolve()
    root = _repo_root(resolved.parent)
    if root is not None:
        try:
            return resolved.relative_to(root).as_posix()
        except ValueError:
            pass
    return Path(os.path.relpath(resolved, os.getcwd())).as_posix()


def _target_path(path: Path, out_dir) -> Path:
    out = Path(out_dir) if out_dir is not None else path.parent / "compiled"
    return out / f"{path.stem}.promises.json"


# -- header merge -------------------------------------------------------------

_DEFAULTS = {"mode": "refute", "domain": "iam", "severity": "medium"}


def _merged(headers, key: str) -> str:
    value = headers.get(key)
    return value if value else _DEFAULTS[key]


# -- the finalizer ------------------------------------------------------------

def _safe_state(p: _Pending) -> str:
    if p.state is not None:
        return p.state
    if p.declared_state in sec_ast.TIERS:
        return p.declared_state
    return "proposal"


def _finalize(p: _Pending) -> sec_artifact.Promise:
    wf = sec_artifact.Wellformedness(
        satisfiable=p.wf_satisfiable,
        non_tautological=p.wf_non_tautological,
        independent=p.wf_independent,
        conflicts_with=p.wf_conflicts,
        notes=p.wf_notes,
    )
    return sec_artifact.Promise(
        id=p.id,
        source=p.source,
        domain=p.domain,
        mode=p.mode,
        state=_safe_state(p),
        severity=p.severity,
        vocabulary=p.vocabulary,
        ast=p.ast,
        sexpr=p.sexpr,
        free_consts=p.free_consts,
        positive=p.positive,
        negative=p.negative,
        wellformedness=wf,
        status=p.status,
        reason=p.reason,
        vocabulary_unverified=p.vocabulary_unverified,
        notes=p.notes,
    )


# -- the per-document pipeline ------------------------------------------------

def compile_document(path, snapshot: GcpSnapshot, *, out_dir=None,
                     check_only: bool = False, independence: bool = True,
                     solver=None) -> CompileResult:
    """Compile one Markdown requirement document into a ``*.promises.json`` artifact."""
    path = Path(path)
    report = GroundingReport()
    rel = _repo_relative(path)
    target = _target_path(path, out_dir)

    # 1. Parse. A ParseError is a document-level abstention.
    try:
        parsed = sec_parse.parse_file(path)
    except sec_parse.ParseError as exc:
        report.add(Verdict("unverified", "sec:doc", rel, 0, f"{rel}: {exc}"))
        return CompileResult(doc=None, report=report, written="", drifted=False)
    for problem in parsed.problems:
        report.add(Verdict("unverified", "sec:doc", rel, 0, f"{rel}: {problem}"))

    # 2. Read the existing artifact, treating any failure as absent.
    prev_by_id: dict[str, sec_artifact.Promise] = {}
    if os.path.exists(target):
        try:
            previous = sec_artifact.load(target)
        except (ValueError, OSError) as exc:
            logger.warning("ignoring unreadable prior artifact %s: %s", target, exc)
        else:
            prev_by_id = {pr.id: pr for pr in previous.promises}

    # 6 (setup). The solver is chosen once; a builtin backend gives z3 is None.
    solver = solver or get_solver()
    z3 = constraints._z3_module(solver)

    # 3. Build a pending record per candidate in sorted-id order.
    pendings: list[_Pending] = []
    for cand in sorted(parsed.candidates, key=lambda c: c.id):
        domain = _merged(cand.headers, "domain")
        mode = _merged(cand.headers, "mode")
        severity = _merged(cand.headers, "severity")
        declared_state = cand.headers.get("state") or None
        text = cand.text or "(no source sentence)"
        source = sec_artifact.Source(file=rel, line=cand.line, text=text)
        p = _Pending(cand, source, domain, mode, severity, declared_state)

        if cand.error:
            p.status = "unverified"
            p.reason = cand.error
            p.ast = None
            report.add(Verdict("unverified", f"sec:{domain}", cand.id, 0,
                               f"{source.file}:{source.line}: {source.text!r} — {cand.error}"))
            pendings.append(p)
            continue

        # Admissible: the parser validated the AST, so free_consts / derived_tier
        # are safe. sexpr is rendered now (pure) so even a later abstention keeps
        # a reviewable form.
        try:
            p.derived = sec_ast.derived_tier(cand.ast)
        except sec_ast.UnknownCollection as exc:
            p.status = "unverified"
            p.reason = str(exc)
            p.ast = None
            report.add(Verdict("unverified", f"sec:{domain}", cand.id, 0,
                               f"{source.file}:{source.line}: {source.text!r} — {exc}"))
            pendings.append(p)
            continue
        p.free_consts = tuple(sec_ast.free_consts(cand.ast))
        p.sexpr = _render_sexpr(cand.ast)
        pendings.append(p)

    admissible = [p for p in pendings if p.status is None]

    # 4. Vocabulary: ground every admissible promise in one Datalog pass.
    grounding = [sec_artifact.Promise(
        id=p.id, source=p.source, domain=p.domain, mode=p.mode,
        state=p.derived, severity=p.severity, vocabulary=p.vocabulary,
        status="unverified", reason="vocabulary grounding") for p in admissible]
    outcomes = sec_vocab.ground_all(grounding, snapshot)
    for p in admissible:
        outcome = outcomes[p.id]
        for verdict in outcome.verdicts:
            report.add(verdict)
        p.vocabulary_unverified = outcome.unverified
        if outcome.ungrounded:
            value = outcome.ungrounded[0]
            p.status = "rejected"
            p.reason = (f"vocabulary is not grounded: {value} does not exist in "
                        f"the snapshot")

    # 5. State cross-check.
    for p in admissible:
        if p.status is not None:
            continue
        derived = p.derived
        if p.declared_state is not None and p.declared_state != derived:
            p.status = "rejected"
            p.reason = (f"declared state {p.declared_state!r} but the promise "
                        f"references {derived!r}-tier collections")
        p.state = derived

    # 6. z3: an absent backend abstains every remaining candidate. Exit is 0.
    if z3 is None:
        for p in admissible:
            if p.status is None:
                p.status = "unverified"
                p.reason = ("z3 is not available (solver backend 'builtin') — the "
                            "promise was not compiled")

    # 7-8. Encode, probe, mint / reuse witnesses.
    for p in admissible:
        if p.status is not None:
            continue
        _encode_probe_and_witness(z3, p, prev_by_id, report)

    # 9. Independence over everything still on the compiled track.
    _run_independence(z3, admissible, independence, report)

    # 10. Assemble.
    doc = PromiseDoc(
        schema=sec_artifact.SEC_SCHEMA,
        source_doc=rel,
        source_sha256=parsed.sha256,
        snapshot_captured_at=snapshot.captured_at,
        encoder=sec_encode.ENCODER_VERSION,
        promises=tuple(_finalize(p) for p in pendings),
    )

    # 11. One status verdict per promise; report.ok fails on a rejected one.
    _status = {"compiled": "grounded", "rejected": "contradicted",
               "unverified": "unverified"}
    for promise in doc.promises:
        message = f"{promise.source.file}:{promise.source.line}: {promise.source.text!r}"
        if promise.reason:
            message += f" — {promise.reason}"
        report.add(Verdict(_status[promise.status], "sec:compile", promise.id, 0, message))

    # 12. Write, or compare in check_only mode.
    written, drifted = _emit(doc, target, check_only, report)
    return CompileResult(doc=doc, report=report, written=written, drifted=drifted)


def _encode_probe_and_witness(z3, p: _Pending, prev_by_id, report) -> None:
    """Steps 7 and 8 for one admissible, non-terminal promise."""
    try:
        formula, consts = sec_encode.symbolic(z3, p.ast)
    except sec_encode.UnsupportedTerm as exc:
        p.status = "unverified"
        p.reason = str(exc)
        return

    obl = sec_probes.obligation(z3, formula, p.mode)
    # The probe interrogates the PATTERN itself: a dead pattern (unsat) can never
    # match a record, a tautological pattern (always true) constrains nothing.
    result = sec_probes.probe(z3, formula, p.ast)
    p.wf_satisfiable = result.satisfiable
    p.wf_non_tautological = result.non_tautological
    p.wf_notes = result.notes

    if result.satisfiable is False:
        p.status = "rejected"
        p.reason = "the promise is unsatisfiable — no record can ever satisfy it"
        return
    if result.non_tautological is False:
        p.status = "rejected"
        p.reason = "the promise is a tautology — it forbids nothing"
        return
    if result.satisfiable is None or result.non_tautological is None:
        p.status = "unverified"
        p.reason = ("z3 could not decide the promise's well-formedness (the solver "
                    "gave up) — the promise was not compiled")
        return

    # 8. Reuse pinned witnesses when the previous artifact carries a byte-identical
    # AST for this id; otherwise mint fresh.
    prev = prev_by_id.get(p.id)
    reuse = (prev is not None and prev.ast is not None and p.ast is not None
             and prev.positive is not None and prev.negative is not None
             and sec_ast.dumps(prev.ast) == sec_ast.dumps(p.ast))
    if reuse:
        p.positive, p.negative = prev.positive, prev.negative
        stub = _WitnessStub(p.ast, p.mode, prev.positive, prev.negative)
        positive_ok, negative_ok = sec_probes.reclassify(z3, stub)
        if positive_ok is False:
            p.status = "rejected"
            p.reason = ("witness drift: the pinned positive witness no longer "
                        "classifies as expected")
            return
        if negative_ok is False:
            p.status = "rejected"
            p.reason = ("witness drift: the pinned negative witness no longer "
                        "classifies as expected")
            return
        if positive_ok is None or negative_ok is None:
            p.status = "unverified"
            p.reason = ("z3 could not re-classify the pinned witnesses (the solver "
                        "gave up) — the promise was not recompiled")
            return
    else:
        positive, negative = sec_probes.mint(z3, obl, consts)
        if positive is None or negative is None:
            p.status = "unverified"
            p.reason = ("z3 could not mint both witnesses (a side was unsatisfiable "
                        "or timed out) — the promise was not compiled")
            return
        p.positive = sec_artifact.Witness(assignment=positive, origin="z3-model")
        p.negative = sec_artifact.Witness(assignment=negative, origin="z3-model")

    # Cleared every probe: this promise compiles. Carry the obligation for the
    # independence pass.
    p.status = "compiled"
    p.reason = ""
    p.obligation = obl
    p.forall_rooted = (sec_ast.is_forall_rooted(p.ast)
                       and not sec_ast.has_existential(p.ast))
    p.collections = tuple(sec_ast.collections_used(p.ast))


class _WitnessStub:
    """A minimal promise-shaped object for :func:`sec_probes.reclassify`."""

    def __init__(self, ast, mode, positive, negative):
        self.ast = ast
        self.mode = mode
        self.positive = positive
        self.negative = negative


def _run_independence(z3, admissible, independence: bool, report) -> None:
    """Step 9: probe the compiled-track promises for pairwise joint-unsat."""
    compiled = [p for p in admissible if p.status == "compiled"]
    entries = [(p.id, p.obligation, p.forall_rooted, p.collections) for p in compiled]
    result = sec_probes.independence(z3, entries, enabled=independence)

    by_id = {p.id: p for p in compiled}
    for p in compiled:
        p.wf_independent = result.independent
        if result.notes:
            p.wf_notes = tuple(p.wf_notes) + tuple(result.notes)

    for conflict in result.conflicts:
        id_a, id_b = conflict.ids
        if conflict.fatal:
            for pid, other in ((id_a, id_b), (id_b, id_a)):
                victim = by_id.get(pid)
                if victim is None:
                    continue
                victim.status = "rejected"
                victim.reason = (f"conflicts with promise {other!r}: no single record "
                                 f"can satisfy both, and both are universally "
                                 f"quantified over a shared collection")
                victim.wf_conflicts = tuple(sorted(set(victim.wf_conflicts) | {other}))
        else:
            for pid, other in ((id_a, id_b), (id_b, id_a)):
                promise = by_id.get(pid)
                if promise is not None:
                    promise.wf_conflicts = tuple(sorted(set(promise.wf_conflicts) | {other}))
            report.add(Verdict(
                "unverified", "sec:compile", f"{id_a} & {id_b}", 0,
                f"promises {id_a!r} and {id_b!r} conflict (no single record satisfies "
                f"both), but the conflict is advisory: they can coexist over "
                f"different records"))


def _emit(doc: PromiseDoc, target: Path, check_only: bool, report):
    """Step 12: write the artifact, or in check_only mode compare against disk."""
    text = sec_artifact.dumps(doc)
    if not check_only:
        sec_artifact.atomic_write(target, text)
        return os.fspath(target), False

    on_disk = None
    if os.path.exists(target):
        try:
            with open(target, encoding="utf-8") as fh:
                on_disk = fh.read()
        except OSError as exc:
            logger.warning("cannot read committed artifact %s: %s", target, exc)
    if on_disk != text:
        report.add(Verdict(
            "contradicted", "sec:artifact", os.fspath(target), 0,
            "the committed artifact does not match a fresh compile of its source — "
            "re-run compile-requirements and commit the result"))
        return "", True
    return "", False


# -- directory driver ---------------------------------------------------------

def compile_directory(directory, snapshot: GcpSnapshot, *, out_dir=None,
                      check_only: bool = False, independence: bool = True,
                      solver=None) -> tuple[CompileResult, ...]:
    """Compile every requirement document directly under *directory*.

    Discovers ``*.md`` files with :func:`sec_parse.discover` (sorted, skipping
    dotfiles / ``README`` / ``TEMPLATE``), compiling each into
    ``out_dir`` (default ``<directory>/compiled``). Returns results in path
    order and never raises on a missing directory.
    """
    out = Path(out_dir) if out_dir is not None else Path(directory) / "compiled"
    results = [compile_document(md, snapshot, out_dir=out, check_only=check_only,
                                independence=independence, solver=solver)
               for md in sec_parse.discover(directory)]
    return tuple(results)
