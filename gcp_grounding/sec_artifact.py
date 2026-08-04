"""The on-disk contract for ``sec_requirements/compiled/<doc-slug>.promises.json``.

Stage 1 of the ``sec_requirements/`` compiler turns each markdown requirement
into a reviewable, git-committed ``*.promises.json`` artifact; this module is
that artifact's schema — pure data plus strict load / deterministic dump. It
imports only :mod:`~gcp_grounding.sec_ast`, :mod:`~gcp_grounding.claims`,
:mod:`gcp_grounding.core.log` and the standard library, so it stays a leaf that
the compiler (``sx-sec-compile``), encoder (``sx-sec-encode``) and vocabulary
grounder (``sx-sec-vocab``) can all depend on.

The artifact is the review boundary and it is committed, so a recompile of
unchanged input MUST be byte-identical: there is deliberately **no wall-clock
field**. Freshness is carried by :attr:`PromiseDoc.snapshot_captured_at` (an
input, copied from ``GcpSnapshot.captured_at``) and provenance by
:attr:`PromiseDoc.source_sha256` (the sha256 of the markdown bytes). Determinism
comes from :func:`dumps` — ``json.dumps(..., sort_keys=True)`` over a tree whose
tuples the dataclasses keep sorted.

Loading is strict, mirroring :meth:`GcpSnapshot.from_dict`
(``knowledge.py:151-155``): a typo must never silently demote a compiled promise
to unverified, so unrecognized keys are rejected at every object level. The
invariants in ``__post_init__`` make it structurally impossible to ship a
``compiled`` promise with no witnesses or an unsatisfiable well-formedness verdict.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from . import claims, sec_ast
from .core.log import get_logger

logger = get_logger(__name__)

__all__ = [
    "SEC_SCHEMA", "STATUSES", "MODES", "DOMAINS", "VOCAB_KINDS", "ORIGINS",
    "Source", "VocabRef", "Witness", "Wellformedness", "Promise", "PromiseDoc",
    "dumps", "load", "atomic_write", "to_claims",
]


# -- constants ----------------------------------------------------------------

#: The schema tag stamped into every artifact; a load rejects any other value.
SEC_SCHEMA = "gcp-sec-promises/1"

#: Compile outcomes. Only ``compiled`` carries a runnable rule; the other two
#: record why a requirement was dropped (``reason`` is then mandatory).
STATUSES = ("compiled", "rejected", "unverified")

#: Polarity of a promise — without it a compiler silently inverts security
#: semantics. ``assert_satisfiable`` = the pattern must hold; ``refute`` = must not.
MODES = ("assert_satisfiable", "refute")

#: The six grounding domains a promise may belong to.
DOMAINS = ("iam", "vpc_firewall", "cloud_armor", "org_policy", "hier_firewall", "vpc_sc")

#: Claim kinds a promise's vocabulary may reference: exactly
#: ``claims.KINDS`` ∩ ``reasoner.EXISTENCE_KINDS`` — the existence questions the
#: Datalog pass can ground before a requirement is admitted. Spelled as a literal
#: (this module must not import ``reasoner``); kept in sync by review.
VOCAB_KINDS = ("role", "permission", "principal", "constraint", "resource_type_ref")

#: Where a witness assignment came from: a fresh z3 model, or a literal pinned
#: at a previous compile and re-classified since.
ORIGINS = ("z3-model", "pinned")

#: A promise id: a dns-label-ish slug so it is safe as a filename fragment and a
#: json-path anchor.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# Allowed keys per object level. A typo in any of these must fail the load, not
# silently demote a promise, so ``from_dict`` rejects anything outside them.
_DOC_KEYS = frozenset({"schema", "source_doc", "source_sha256",
                       "snapshot_captured_at", "encoder", "promises"})
_PROMISE_KEYS = frozenset({"id", "source", "domain", "mode", "state", "severity",
                           "vocabulary", "smt", "witnesses", "wellformedness",
                           "status", "reason", "vocabulary_unverified", "notes"})
_SMT_KEYS = frozenset({"ast", "sexpr", "free_consts"})
_WITNESSES_KEYS = frozenset({"positive", "negative"})
_WITNESS_KEYS = frozenset({"assignment", "origin"})
_WF_KEYS = frozenset({"satisfiable", "non_tautological", "independent",
                      "probe_scope", "conflicts_with", "notes"})
_SOURCE_KEYS = frozenset({"file", "line", "text"})
_VOCAB_KEYS = frozenset({"kind", "value"})


def _reject_unknown(data: Mapping[str, Any], allowed, where: str) -> None:
    """Raise if *data* carries any key outside *allowed*, naming the strays."""
    extra = sorted(set(data) - set(allowed))
    if extra:
        raise ValueError(f"unrecognized {where} keys {extra} — a typo must not "
                         f"silently demote a promise; expected only {sorted(allowed)}")


# -- leaf dataclasses ---------------------------------------------------------


@dataclass(frozen=True)
class Source:
    """The markdown sentence a promise came from, anchored to its file/line."""

    file: str = ""
    line: int = 0
    text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "text": self.text}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Source":
        if not isinstance(data, Mapping):
            raise ValueError(f"'source' must be an object, got {type(data).__name__}")
        _reject_unknown(data, _SOURCE_KEYS, "source")
        return cls(file=data.get("file", ""), line=data.get("line", 0),
                   text=data.get("text", ""))


@dataclass(frozen=True)
class VocabRef:
    """A ``Claim``-shaped existence reference the requirement makes."""

    kind: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VocabRef":
        if not isinstance(data, Mapping):
            raise ValueError(f"vocabulary entry must be an object, got {type(data).__name__}")
        _reject_unknown(data, _VOCAB_KEYS, "vocabulary entry")
        return cls(kind=data.get("kind"), value=data.get("value"))


@dataclass(frozen=True)
class Witness:
    """A concrete assignment satisfying (positive) or violating (negative) a
    promise: free-const name → a literal that is always a string."""

    assignment: Mapping[str, str]
    origin: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "assignment", dict(self.assignment))
        for name, value in self.assignment.items():
            if not isinstance(value, str):
                raise ValueError(f"witness assignment[{name!r}] must be a string "
                                 f"literal, got {value!r}")
        if self.origin not in ORIGINS:
            raise ValueError(f"witness origin {self.origin!r} not in {ORIGINS}")

    def to_dict(self) -> dict[str, Any]:
        return {"assignment": dict(self.assignment), "origin": self.origin}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Witness":
        if not isinstance(data, Mapping):
            raise ValueError(f"witness must be an object, got {type(data).__name__}")
        _reject_unknown(data, _WITNESS_KEYS, "witness")
        return cls(assignment=data.get("assignment") or {}, origin=data.get("origin"))


@dataclass(frozen=True)
class Wellformedness:
    """The compile-time probe verdicts for one promise. ``None`` means the probe
    was skipped; ``probe_scope`` is always ``per_record``."""

    satisfiable: bool | None = None
    non_tautological: bool | None = None
    independent: bool | None = None
    probe_scope: str = "per_record"
    conflicts_with: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "conflicts_with", tuple(self.conflicts_with))
        object.__setattr__(self, "notes", tuple(self.notes))
        if self.probe_scope != "per_record":
            raise ValueError(f"wellformedness.probe_scope must be 'per_record', "
                             f"got {self.probe_scope!r}")
        for name, value in (("satisfiable", self.satisfiable),
                            ("non_tautological", self.non_tautological),
                            ("independent", self.independent)):
            if value is not None and not isinstance(value, bool):
                raise ValueError(f"wellformedness.{name} must be a bool or None, "
                                 f"got {value!r}")

    def to_dict(self) -> dict[str, Any]:
        return {"satisfiable": self.satisfiable,
                "non_tautological": self.non_tautological,
                "independent": self.independent,
                "probe_scope": self.probe_scope,
                "conflicts_with": list(self.conflicts_with),
                "notes": list(self.notes)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Wellformedness":
        if not isinstance(data, Mapping):
            raise ValueError(f"'wellformedness' must be an object, "
                             f"got {type(data).__name__}")
        _reject_unknown(data, _WF_KEYS, "wellformedness")
        return cls(
            satisfiable=data.get("satisfiable"),
            non_tautological=data.get("non_tautological"),
            independent=data.get("independent"),
            probe_scope=data.get("probe_scope", "per_record"),
            conflicts_with=tuple(data.get("conflicts_with") or ()),
            notes=tuple(data.get("notes") or ()),
        )


# -- the promise --------------------------------------------------------------


@dataclass(frozen=True)
class Promise:
    """One compiled (or rejected / unverified) security requirement."""

    id: str = ""
    source: Source = field(default_factory=Source)
    domain: str = ""
    mode: str = ""
    state: str = ""
    severity: str = ""
    vocabulary: tuple[VocabRef, ...] = ()
    ast: dict | None = None
    sexpr: str = ""
    free_consts: tuple[tuple[str, str], ...] = ()
    positive: Witness | None = None
    negative: Witness | None = None
    wellformedness: Wellformedness = field(default_factory=Wellformedness)
    status: str = ""
    reason: str = ""
    vocabulary_unverified: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "vocabulary", tuple(self.vocabulary))
        object.__setattr__(self, "free_consts",
                           tuple(tuple(fc) for fc in self.free_consts))
        object.__setattr__(self, "vocabulary_unverified",
                           tuple(self.vocabulary_unverified))
        object.__setattr__(self, "notes", tuple(self.notes))

        pid = self.id
        if not isinstance(pid, str) or not _ID_RE.match(pid):
            raise ValueError(f"promise id {pid!r} must match {_ID_RE.pattern!r}")
        if self.mode not in MODES:
            raise ValueError(f"promise {pid!r}: mode {self.mode!r} not in {MODES}")
        if self.domain not in DOMAINS:
            raise ValueError(f"promise {pid!r}: domain {self.domain!r} not in {DOMAINS}")
        if self.state not in sec_ast.TIERS:
            raise ValueError(f"promise {pid!r}: state {self.state!r} not in {sec_ast.TIERS}")
        if self.status not in STATUSES:
            raise ValueError(f"promise {pid!r}: status {self.status!r} not in {STATUSES}")
        if self.status == "compiled":
            if self.reason:
                raise ValueError(f"promise {pid!r}: a compiled promise must have an "
                                 f"empty reason, got {self.reason!r}")
        elif not self.reason:
            raise ValueError(f"promise {pid!r}: status {self.status!r} requires a "
                             f"non-empty reason")
        if not isinstance(self.source, Source) or not self.source.text:
            raise ValueError(f"promise {pid!r}: source.text must be non-empty")
        for ref in self.vocabulary:
            if ref.kind not in VOCAB_KINDS:
                raise ValueError(f"promise {pid!r}: vocabulary kind {ref.kind!r} "
                                 f"not in {VOCAB_KINDS}")

        if self.status == "compiled":
            if self.ast is None:
                raise ValueError(f"promise {pid!r}: a compiled promise requires a "
                                 f"non-None ast")
            if not self.sexpr:
                raise ValueError(f"promise {pid!r}: a compiled promise requires a "
                                 f"non-empty sexpr")
            if self.positive is None or self.negative is None:
                raise ValueError(f"promise {pid!r}: a compiled promise requires BOTH "
                                 f"positive and negative witnesses")
            wf = self.wellformedness
            if not (wf.satisfiable is True and wf.non_tautological is True):
                raise ValueError(f"promise {pid!r}: a compiled promise requires "
                                 f"wellformedness.satisfiable and non_tautological "
                                 f"to be True")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source.to_dict(),
            "domain": self.domain,
            "mode": self.mode,
            "state": self.state,
            "severity": self.severity,
            "vocabulary": [ref.to_dict() for ref in self.vocabulary],
            "smt": {
                "ast": self.ast,
                "sexpr": self.sexpr,
                "free_consts": [[name, sort] for name, sort in self.free_consts],
            },
            "witnesses": {
                "positive": self.positive.to_dict() if self.positive is not None else None,
                "negative": self.negative.to_dict() if self.negative is not None else None,
            },
            "wellformedness": self.wellformedness.to_dict(),
            "status": self.status,
            "reason": self.reason,
            "vocabulary_unverified": list(self.vocabulary_unverified),
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Promise":
        if not isinstance(data, Mapping):
            raise ValueError(f"promise must be an object, got {type(data).__name__}")
        _reject_unknown(data, _PROMISE_KEYS, "promise")
        pid = data.get("id")

        smt = data.get("smt")
        if not isinstance(smt, Mapping):
            raise ValueError(f"promise {pid!r}: 'smt' must be an object")
        _reject_unknown(smt, _SMT_KEYS, "smt")
        ast = smt.get("ast")
        if ast is not None:
            try:
                sec_ast.validate(ast)
            except (sec_ast.InvalidAst, sec_ast.UnknownCollection) as exc:
                raise ValueError(f"promise {pid!r}: invalid ast: {exc}") from exc
        free_consts = tuple(tuple(fc) for fc in (smt.get("free_consts") or ()))

        witnesses = data.get("witnesses")
        if not isinstance(witnesses, Mapping):
            raise ValueError(f"promise {pid!r}: 'witnesses' must be an object")
        _reject_unknown(witnesses, _WITNESSES_KEYS, "witnesses")
        raw_pos, raw_neg = witnesses.get("positive"), witnesses.get("negative")
        positive = Witness.from_dict(raw_pos) if raw_pos is not None else None
        negative = Witness.from_dict(raw_neg) if raw_neg is not None else None

        wf = data.get("wellformedness")
        wellformedness = Wellformedness.from_dict(wf)

        vocabulary = tuple(VocabRef.from_dict(v) for v in (data.get("vocabulary") or ()))

        return cls(
            id=pid,
            source=Source.from_dict(data.get("source")),
            domain=data.get("domain"),
            mode=data.get("mode"),
            state=data.get("state"),
            severity=data.get("severity"),
            vocabulary=vocabulary,
            ast=ast,
            sexpr=smt.get("sexpr", ""),
            free_consts=free_consts,
            positive=positive,
            negative=negative,
            wellformedness=wellformedness,
            status=data.get("status"),
            reason=data.get("reason", ""),
            vocabulary_unverified=tuple(data.get("vocabulary_unverified") or ()),
            notes=tuple(data.get("notes") or ()),
        )


# -- the document -------------------------------------------------------------


@dataclass(frozen=True)
class PromiseDoc:
    """A whole ``*.promises.json`` artifact: schema, provenance and the promises
    compiled from one markdown document, kept sorted by id."""

    schema: str = SEC_SCHEMA
    source_doc: str = ""
    source_sha256: str = ""
    snapshot_captured_at: str = ""
    encoder: str = ""
    promises: tuple[Promise, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "promises",
                           tuple(sorted(self.promises, key=lambda p: p.id)))
        if self.schema != SEC_SCHEMA:
            raise ValueError(f"schema {self.schema!r} is not {SEC_SCHEMA!r}")
        ids = [p.id for p in self.promises]
        dupes = sorted({pid for pid in ids if ids.count(pid) > 1})
        if dupes:
            raise ValueError(f"duplicate promise ids {dupes}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "source_doc": self.source_doc,
            "source_sha256": self.source_sha256,
            "snapshot_captured_at": self.snapshot_captured_at,
            "encoder": self.encoder,
            "promises": [p.to_dict() for p in self.promises],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PromiseDoc":
        if not isinstance(data, Mapping):
            raise ValueError(f"promise document must be an object, "
                             f"got {type(data).__name__}")
        _reject_unknown(data, _DOC_KEYS, "document")
        schema = data.get("schema")
        if schema != SEC_SCHEMA:
            raise ValueError(f"unknown schema {schema!r}; expected {SEC_SCHEMA!r}")
        raw = data.get("promises")
        if raw is None:
            raw = []
        if not isinstance(raw, list):
            raise ValueError(f"'promises' must be a list, got {type(raw).__name__}")
        return cls(
            schema=schema,
            source_doc=data.get("source_doc", ""),
            source_sha256=data.get("source_sha256", ""),
            snapshot_captured_at=data.get("snapshot_captured_at", ""),
            encoder=data.get("encoder", ""),
            promises=tuple(Promise.from_dict(p) for p in raw),
        )


# -- serialization ------------------------------------------------------------


def dumps(doc: PromiseDoc) -> str:
    """Deterministic UTF-8 JSON text for *doc*, with a trailing newline.

    ``sort_keys=True`` over dataclass-sorted tuples makes a recompile of
    unchanged input byte-identical, which is what lets the artifact be reviewed
    by diff. Mirrors ``sec_ast.dumps`` / ``fetch.write_snapshot``.
    """
    return json.dumps(doc.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def load(path: str | os.PathLike[str]) -> PromiseDoc:
    """Load and strictly validate a ``*.promises.json`` file.

    Wraps every failure as ``ValueError(f"{path}: {exc}")``, mirroring
    :meth:`GcpSnapshot.load` (``knowledge.py:139-142``).
    """
    with open(path, encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: {exc}") from exc
    try:
        doc = PromiseDoc.from_dict(data)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc
    logger.debug("loaded promise doc %s (%d promise(s), source_doc=%s)",
                 path, len(doc.promises), doc.source_doc)
    return doc


def atomic_write(path: str | os.PathLike[str], text: str) -> None:
    """Write *text* to *path* atomically, leaving no ``.tmp`` behind.

    Creates the parent directories, writes the UTF-8 bytes to a sibling
    ``<name>.tmp`` in the same directory (so ``os.replace`` stays within one
    filesystem and is therefore atomic), then replaces the target. On any
    failure the temp file is removed. No locking is needed: a single process
    writes each artifact.
    """
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        raise


# -- interop with the existence grounder --------------------------------------


def to_claims(promise: Promise) -> list[claims.Claim]:
    """One :class:`~gcp_grounding.claims.Claim` per vocabulary entry, anchored to
    its json-path in the promise (for ``sx-sec-vocab``)."""
    return [
        claims.Claim(kind=ref.kind, value=ref.value,
                     location=f"{promise.id}#vocabulary[{i}]")
        for i, ref in enumerate(promise.vocabulary)
    ]
