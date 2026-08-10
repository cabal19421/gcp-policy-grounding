"""Optional, opt-in LLM assist: a CANDIDATE GENERATOR and nothing more.

Everything in this module produces *candidates*. Nothing it produces bypasses
stage 1's deterministic verification, and that is the whole point.

THE CONTRACT. The model emits the SAME authoring syntax a human writes — one
fenced ``promise`` block — never a JSON AST and never Python. A block is then
re-parsed by :mod:`gcp_grounding.sec_parse`, re-grounded by
:mod:`gcp_grounding.sec_vocab` and re-probed by :mod:`gcp_grounding.sec_probes`,
exactly as if a person had typed it. THE SAFETY CHAIN follows from that one
decision:

- a hallucinated **role** dies at vocabulary grounding, with the same
  did-you-mean suggester that catches the typo in a policy — ``roles/bigquery.reader``
  is ``rejected`` and points at ``roles/bigquery.dataViewer``;
- a hallucinated **node keyword** dies in the parser — ``unknown smt keyword``
  becomes the candidate's ``error`` and the promise compiles to ``unverified``,
  never to a rule;
- a **vacuous** rule dies at the non-tautology probe — a promise that forbids
  nothing is ``rejected``;
- a **dead** rule dies at the satisfiability probe — a pattern no record can
  match is ``rejected``;
- an **inverted** rule (right shape, wrong polarity) is caught by the reviewer
  reading the pinned positive and negative witnesses, which is why witnesses are
  mandatory and pinned as literals.

There is no path from this module into the gate that skips those steps: it never
writes an artifact, never registers a check, and never constructs an AST itself.

OPT IN TWICE. :func:`available` is True only when ``GCP_SEC_LLM=1`` *and*
``GCP_SEC_LLM_CMD`` names a command whose executable is on ``PATH``. The default
runner shells out to that command and is NEVER exercised by the test suite;
every test injects its own ``runner``. No vendor binary and no model id is
hardcoded — the operator writes the whole command line, model flags included,
into ``GCP_SEC_LLM_CMD``, so this module cannot go stale.

THE REVIEW MARKER. :func:`annotate_document` writes each proposed block into the
markdown with :data:`MARKER` as the first line inside the block. Its presence
forces status ``unverified`` with reason :data:`REVIEW_REASON` no matter how
cleanly the promise probes; a human deleting that line is the admission act.
The design places those two hooks in ``sec_parse`` (skip hash-comment lines) and
``sec_compile`` (honour the marker). This checkout has neither, and this task
owns only this module, so the marker is honoured LOCALLY: :func:`marked_ids`
scans the raw block text and :func:`compile_with_review` overrides the status of
every promise it names. Until the parser learns to skip hash comments, a marked
block additionally fails to parse (the marker reads as an unknown header key),
which lands in the same honest bucket — ``unverified``, never a silent pass.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Mapping, Optional

from . import sec_artifact, sec_ast, sec_compile
from .core.log import get_logger
from .core.report import GroundingReport, Verdict

logger = get_logger(__name__)

__all__ = [
    "LLM_ENV", "LLM_CMD_ENV", "LLM_TIMEOUT_ENV", "DEFAULT_TIMEOUT",
    "MARKER", "REVIEW_REASON", "SMT_KEYWORDS", "TERM_KEYWORDS",
    "LlmUnavailable", "available", "build_prompt", "propose_block",
    "extract_block", "annotate_document", "marked_ids", "compile_with_review",
]


# -- environment --------------------------------------------------------------

#: Must equal exactly ``"1"`` to enable the assist. Half of the opt-in.
LLM_ENV = "GCP_SEC_LLM"

#: The command line the default runner executes — split with :func:`shlex.split`,
#: prompt on stdin. The other half of the opt-in: unset means unavailable, which
#: is why no vendor command and no model id appears anywhere in this file.
LLM_CMD_ENV = "GCP_SEC_LLM_CMD"

#: Subprocess timeout in seconds; unset or unparseable means
#: :data:`DEFAULT_TIMEOUT`.
LLM_TIMEOUT_ENV = "GCP_SEC_LLM_TIMEOUT"

#: Seconds allowed for one CLI invocation.
DEFAULT_TIMEOUT = 120.0

#: The first line inside every generated block. Byte-exact: the review workflow
#: keys off this string, and a human deleting the line is the admission act.
MARKER = "# generated: needs review — remove this line to admit this promise"

#: The compile reason a marked promise carries, whatever the probes say.
REVIEW_REASON = "LLM-proposed, awaiting human review"


class LlmUnavailable(Exception):
    """The assist could not produce a candidate; the reason is the message."""


def _command() -> list[str]:
    """The argv :data:`LLM_CMD_ENV` names, or ``[]`` when unset or unsplittable."""
    raw = os.environ.get(LLM_CMD_ENV, "")
    if not raw.strip():
        return []
    try:
        return shlex.split(raw)
    except ValueError as exc:
        logger.warning("%s=%r cannot be split into a command: %s",
                       LLM_CMD_ENV, raw, exc)
        return []


def available() -> bool:
    """True only when the env var is exactly ``"1"`` AND :data:`LLM_CMD_ENV`
    names a command whose executable is on ``PATH``."""
    argv = _command()
    return (os.environ.get(LLM_ENV) == "1" and bool(argv)
            and shutil.which(argv[0]) is not None)


def _timeout() -> float:
    raw = os.environ.get(LLM_TIMEOUT_ENV, "")
    if not raw.strip():
        return DEFAULT_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        logger.warning("%s=%r is not a number; using %ss", LLM_TIMEOUT_ENV, raw,
                       DEFAULT_TIMEOUT)
        return DEFAULT_TIMEOUT
    if value <= 0:
        logger.warning("%s=%r is not positive; using %ss", LLM_TIMEOUT_ENV, raw,
                       DEFAULT_TIMEOUT)
        return DEFAULT_TIMEOUT
    return value


# -- the prompt ---------------------------------------------------------------
#
# The keyword tables mirror ``sec_parse._make_node`` and ``sec_parse._parse_term``
# exactly; they are the surface syntax, not the JSON AST, because the surface
# syntax is what a human writes and therefore what gets re-parsed.

_KEYWORD_TABLE: tuple[tuple[str, str, str], ...] = (
    ("true", "true", "the constant true; no operands, no child lines"),
    ("false", "false", "the constant false; no operands, no child lines"),
    ("not", "not", "negation; exactly one child line"),
    ("and", "and", "conjunction; one or more child lines"),
    ("or", "or", "disjunction; one or more child lines"),
    ("implies", "implies", "implication; exactly two child lines (antecedent, consequent)"),
    ("atmost", "atmost <k>",
     "at most k of the child lines hold; one or more child lines"),
    ("atleast", "atleast <k>",
     "at least k of the child lines hold; one or more child lines"),
    ("forall", "forall <var> in <collection>",
     "universal quantifier; exactly one child line"),
    ("exists", "exists <var> in <collection>",
     "existential quantifier; exactly one child line"),
    ("cmp", "cmp <op> <term> <term>",
     "compare two same-sorted terms; <op> is one of eq, ne, lt, le, gt, ge "
     "(lt/le/gt/ge are undefined on Str and Bool); no child lines"),
    ("in", 'in <term> set["a", "b"]', "Str membership in a literal set; no child lines"),
    ("prefix", 'prefix <term> "text"',
     "the Str term starts with the literal; no child lines"),
    ("suffix", 'suffix <term> "text"',
     "the Str term ends with the literal; no child lines"),
    ("contains", 'contains <term> "text"',
     "the Str term contains the literal; no child lines"),
    ("cidr_contains", "cidr_contains <Cidr term> <Ip4 term>",
     "the CIDR block contains the address; no child lines"),
    ("port_in", "port_in <term> <lo> <hi>",
     "the term lies in the inclusive port range 0..65535; no child lines"),
    ("cel", 'cel "<expression>"',
     "an opaque CEL condition. THE ENCODER REFUSES IT: a cel promise is always "
     "unverified and never becomes a rule. Do not emit it."),
)

_TERM_TABLE: tuple[tuple[str, str, str], ...] = (
    ("field", "field <var>.<field>",
     "a field of a quantifier-bound record; its sort comes from the collection"),
    ("str", 'str "text"', "a Str literal"),
    ("int", "int <n>", "an Int literal"),
    ("port", "port <n>", "a Port literal, 0..65535"),
    ("ip4", 'ip4 "10.0.0.1"', "an Ip4 literal, a dotted quad"),
    ("cidr", 'cidr "10.0.0.0/8"',
     "a Cidr literal; it may appear ONLY as the first operand of cidr_contains"),
    ("bool", "bool true|false", "a Bool literal"),
    ("set", 'set["a", "b"]',
     "a literal set of quoted strings; it may appear ONLY as the second operand of in"),
)

#: Every formula keyword the parser accepts, in table order.
SMT_KEYWORDS: tuple[str, ...] = tuple(kw for kw, _shape, _gloss in _KEYWORD_TABLE)

#: Every term keyword the parser accepts, in table order.
TERM_KEYWORDS: tuple[str, ...] = tuple(kw for kw, _shape, _gloss in _TERM_TABLE)

_MODE_GLOSS = {
    "assert_satisfiable": ("the pattern MUST hold — the requirement says this is "
                           "how the world should look"),
    "refute": ("the pattern MUST NOT hold — the requirement forbids anything "
               "matching it"),
}


def _registry(collections) -> Mapping[str, sec_ast.CollectionSpec]:
    """The collection registry to describe: the caller's, or the global one.

    Resolving the global registry first triggers the same lazy, fail-open domain
    import ``sec_ast.validate`` performs, so the prompt describes exactly the
    collections the parser will accept in this checkout — never more.
    """
    if collections is not None:
        return dict(collections)
    sec_ast._ensure_domains()
    return dict(sec_ast.COLLECTIONS)


def _table(rows) -> str:
    """One ``  <shape>`` line per row, its gloss indented beneath it."""
    return "\n".join(f"  {shape}\n      {gloss}" for _kw, shape, gloss in rows)


def _collection_lines(registry) -> list[str]:
    out = []
    for name in sorted(registry):
        spec = registry[name]
        fields = ", ".join(f"{f}: {s}" for f, s in sorted(spec.fields.items()))
        out.append(f"  {name} (tier {spec.tier}) — {fields}")
    return out


def build_prompt(section_text: str, *, collections=None) -> str:
    """The full prompt for one requirement sentence. Pure and deterministic.

    Embeds the sentence, the exact ``smt`` keyword and term tables, every
    registered collection with its field sorts, the ``mode`` polarity
    definition, and the hard one-block output rule. Given the same sentence and
    the same registry it returns byte-identical text: every table is fixed and
    every mapping is walked in sorted order.
    """
    registry = _registry(collections)
    modes = "\n".join(f"  {mode} — {_MODE_GLOSS[mode]}" for mode in sec_artifact.MODES)
    keywords = _table(_KEYWORD_TABLE)
    terms = _table(_TERM_TABLE)
    collection_block = "\n".join(_collection_lines(registry)) or "  (none registered)"
    vocab_kinds = ", ".join(sec_artifact.VOCAB_KINDS)
    return f"""\
You are translating ONE security requirement sentence into ONE machine-checkable
promise block for a GCP policy gate. Your output is a CANDIDATE: it is re-parsed,
re-grounded against a real snapshot and re-probed by a solver before anyone
trusts it. Guessing a role name or a keyword does not sneak anything past the
gate; it only wastes a review cycle.

THE REQUIREMENT SENTENCE
{section_text}

MODE — the polarity of the promise. Getting this wrong inverts the security
meaning of the rule, so choose it from the sentence, not from habit:
{modes}

COLLECTIONS you may quantify over, with the sorts of their fields. Quantifying
over anything else is an error:
{collection_block}

SMT KEYWORDS. The body of `smt:` is prefix notation, one keyword per line.
Child lines are indented exactly two spaces deeper than their parent; tabs are
forbidden; the body must be a single formula with one root line:
{keywords}

TERMS. Operands appear inline on the keyword's own line:
{terms}

VOCABULARY. Every role, permission, principal, constraint or resource type the
requirement names must be declared with its own `vocab: <kind> <value>` header
line, where <kind> is one of {vocab_kinds}. Each declared
value is checked for existence against the real snapshot; an invented one is
rejected with a did-you-mean. Declare only values you are confident exist, and
spell them exactly as GCP does.

OUTPUT — read this twice:
- Emit exactly ONE fenced block, opened by a line reading ```promise and closed
  by a line reading ```. Emit NOTHING else: no prose, no explanation, no second
  block, no JSON.
- The first two header lines are `id:` and `mode:`. The id must match
  {sec_artifact._ID_RE.pattern!r} — a lowercase hyphenated slug derived from the
  requirement.
- Optional header lines: `domain:`, `state:`, `severity:`, `vocab:` (repeatable),
  `note:` (repeatable).
- The last header is `smt:` with an empty value; the formula follows on the
  indented lines beneath it.

Example of the required shape and nothing more:

```promise
id: no-primitive-owner
mode: refute
smt:
  exists b in iam_bindings
    cmp eq field b.role str "roles/owner"
```
"""


# -- the runner seam ----------------------------------------------------------

def _default_runner(prompt: str) -> str:
    """Run the configured LLM command. NEVER exercised by the test suite.

    The command line is :data:`LLM_CMD_ENV` verbatim — argv via
    :func:`shlex.split`, the prompt on stdin, the reply on stdout either as
    plain text or as a JSON ``{"result": ...}`` envelope (:func:`_unwrap`
    accepts both). Every failure mode — missing executable, timeout, non-zero
    exit — raises :class:`LlmUnavailable` naming the reason.
    """
    argv = _command()
    if not argv:
        raise LlmUnavailable(f"{LLM_CMD_ENV} does not name a command")
    timeout = _timeout()
    try:
        proc = subprocess.run(argv, input=prompt, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise LlmUnavailable(f"the LLM command {argv[0]!r} is not on PATH: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise LlmUnavailable(f"the LLM command did not answer within {timeout}s") from exc
    except OSError as exc:
        raise LlmUnavailable(f"the LLM command could not be run: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        tail = detail[-1] if detail else "no stderr"
        raise LlmUnavailable(f"the LLM command exited {proc.returncode}: {tail}")
    return _unwrap(proc.stdout)


def _unwrap(stdout: str) -> str:
    """The model text in *stdout*: a JSON envelope's ``result``, or the bytes
    as-is.

    Some CLIs emit a ``{"result": "<text>"}`` JSON envelope instead of the bare
    reply; both shapes are accepted. Anything that is not that envelope is
    returned verbatim as plain text — the strict fence extraction downstream
    rejects a non-answer in the open, so nothing is guessed at here.
    """
    try:
        payload = json.loads(stdout)
    except ValueError:
        return stdout
    if isinstance(payload, Mapping):
        result = payload.get("result")
        if isinstance(result, str):
            return result
    return stdout


# -- extraction ---------------------------------------------------------------

def extract_block(text: str) -> str:
    """The one fenced ``promise`` block in *text*, verbatim and unrepaired.

    Zero blocks, more than one, or an unterminated fence raises
    :class:`LlmUnavailable`. Nothing is reformatted and no missing header is
    filled in: a block the parser rejects must reach the parser and be rejected
    there, in the open.
    """
    if not isinstance(text, str):
        raise LlmUnavailable(f"the runner returned {type(text).__name__}, not text")
    lines = text.split("\n")
    _sections, blocks, unterminated = _scan(lines)
    if unterminated:
        raise LlmUnavailable("the model left a fence unterminated")
    if not blocks:
        raise LlmUnavailable("the model emitted no ```promise fence")
    if len(blocks) > 1:
        raise LlmUnavailable(f"the model emitted {len(blocks)} promise fences; "
                             f"exactly one is required")
    start, end = blocks[0]
    return "\n".join(lines[start:end + 1])


def propose_block(section_text: str, *, runner=None, collections=None) -> str:
    """Ask for one promise block for *section_text* and return it verbatim.

    *runner* is the seam: a ``Callable[[str], str]`` taking the prompt and
    returning raw model text. Passing one keeps this function entirely offline,
    which is how every test drives it. With ``runner=None`` the default CLI
    runner is used, and only then is the twice-over opt-in required.
    """
    prompt = build_prompt(section_text, collections=collections)
    call: Optional[Callable[[str], str]] = runner
    if call is None:
        if not available():
            raise LlmUnavailable(
                f"the LLM assist is off: set {LLM_ENV}=1 and point {LLM_CMD_ENV} "
                f"at an on-PATH command, or pass an explicit runner")
        call = _default_runner
    return extract_block(call(prompt))


# -- markdown scanning --------------------------------------------------------
#
# Deliberately mirrors ``sec_parse._scan_sections``: this module must agree with
# the parser about what a section and a promise block are, or it would annotate
# a document the parser reads differently.

@dataclasses.dataclass(frozen=True)
class _Section:
    heading: str
    line: int          # 1-based line number of the '## ' heading
    start: int         # 0-based index of the heading line
    end: int           # 0-based index one past the section's last line
    sentence: str
    has_promise: bool


def _scan(lines) -> tuple[tuple[_Section, ...], list[tuple[int, int]], bool]:
    """Return ``(sections, promise_block_spans, unterminated_fence)``.

    A span is ``(open_fence_index, close_fence_index)``, both inclusive.
    """
    raw_sections: list[dict] = []
    blocks: list[tuple[int, int]] = []
    cur: Optional[dict] = None
    in_fence = fence_is_promise = False
    open_idx = -1
    for idx, raw in enumerate(lines):
        stripped = raw.strip()
        if in_fence:
            if stripped.startswith("```"):
                in_fence = False
                if fence_is_promise:
                    blocks.append((open_idx, idx))
                    if cur is not None:
                        cur["has_promise"] = True
                fence_is_promise = False
            continue
        if stripped.startswith("```"):
            in_fence = True
            fence_is_promise = stripped[3:].strip() == "promise"
            open_idx = idx
            continue
        if raw.startswith("## "):
            cur = {"heading": stripped[3:].strip(), "start": idx, "sentence": "",
                   "has_promise": False}
            raw_sections.append(cur)
            continue
        if stripped.startswith("#"):
            continue
        if cur is not None and not cur["sentence"] and stripped:
            cur["sentence"] = raw.strip()
    sections = []
    for i, sec in enumerate(raw_sections):
        end = raw_sections[i + 1]["start"] if i + 1 < len(raw_sections) else len(lines)
        sections.append(_Section(heading=sec["heading"], line=sec["start"] + 1,
                                 start=sec["start"], end=end,
                                 sentence=sec["sentence"],
                                 has_promise=sec["has_promise"]))
    return tuple(sections), blocks, in_fence


def _block_id(body) -> str:
    """The ``id:`` header of a block body, or ``""``."""
    for raw in body:
        key, sep, value = raw.partition(":")
        if sep and key.strip() == "id":
            return value.strip()
        if sep and key.strip() == "smt":
            break
    return ""


def marked_ids(text: str) -> frozenset[str]:
    """The ids of every promise block in *text* carrying :data:`MARKER`.

    The local stand-in for the ``sec_compile`` marker hook: it reads the raw
    block text, so it sees the marker whether or not the parser can.
    """
    lines = text.split("\n")
    _sections, blocks, _unterminated = _scan(lines)
    out = set()
    for start, end in blocks:
        body = lines[start + 1:end]
        if any(raw.strip() == MARKER for raw in body):
            ident = _block_id(body)
            if ident:
                out.add(ident)
    return frozenset(out)


def _with_marker(block: str) -> list[str]:
    """The block's lines with :data:`MARKER` inserted just inside the fence."""
    lines = block.split("\n")
    return [lines[0], MARKER, *lines[1:]]


# -- write-back ---------------------------------------------------------------

def annotate_document(path, *, runner=None, dry_run=True,
                      collections=None) -> tuple[str, tuple[str, ...]]:
    """Propose a promise block for every un-promised section of *path*.

    Each proposal is appended inside its own section, marker line first. Returns
    ``(new_text, warnings)`` either way; ``dry_run=False`` is the only thing that
    ever touches disk, and it writes through
    :func:`~gcp_grounding.sec_artifact.atomic_write`. A section that already
    carries a promise, a section with no sentence, and a section the assist could
    not answer for are each left exactly as they were and named in *warnings*.
    """
    path = Path(path)
    original = path.read_text(encoding="utf-8")
    lines = original.split("\n")
    sections, _blocks, unterminated = _scan(lines)
    warnings: list[str] = []
    if unterminated:
        warnings.append(f"{path.name}: a fence is unterminated; nothing was proposed")
        return original, tuple(warnings)

    proposals: list[tuple[_Section, list[str]]] = []
    for section in sections:
        where = f"{path.name}:{section.line}: section {section.heading!r}"
        if section.has_promise:
            warnings.append(f"{where} already carries a promise block — left unchanged")
            continue
        if not section.sentence:
            warnings.append(f"{where} has no requirement sentence — left unchanged")
            continue
        try:
            block = propose_block(section.sentence, runner=runner,
                                  collections=collections)
        except LlmUnavailable as exc:
            warnings.append(f"{where} was not annotated: {exc}")
            continue
        proposals.append((section, _with_marker(block)))
    if not sections:
        warnings.append(f"{path.name}: no '## ' sections — nothing was proposed")

    new_text = _splice(lines, proposals)
    if not dry_run and new_text != original:
        sec_artifact.atomic_write(path, new_text)
    return new_text, tuple(warnings)


def _splice(lines, proposals) -> str:
    """Insert each proposal's lines at the end of its section."""
    out: list[str] = []
    cursor = 0
    for section, block in sorted(proposals, key=lambda pair: pair[0].end):
        out.extend(lines[cursor:section.end])
        while out and not out[-1].strip():
            out.pop()
        out.append("")
        out.extend(block)
        out.append("")
        cursor = section.end
    out.extend(lines[cursor:])
    return "\n".join(out)


# -- compiling a document that may carry the marker ---------------------------

def compile_with_review(path, snapshot, *, out_dir=None, check_only: bool = False,
                        independence: bool = True, solver=None):
    """:func:`~gcp_grounding.sec_compile.compile_document` plus the marker rule.

    Every promise whose block carries :data:`MARKER` is forced to status
    ``unverified`` with reason :data:`REVIEW_REASON`, however cleanly it probed;
    the artifact is re-emitted (or, in ``check_only`` mode, re-compared) from the
    corrected document so the committed bytes say the same thing. Unmarked
    promises are untouched — they take the ordinary compiled/rejected/unverified
    verdict, which is the point: the marker only ever weakens a verdict.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raw = ""  # sec_compile reports the unreadable file honestly on its own.
    marked = marked_ids(raw)
    result = sec_compile.compile_document(path, snapshot, out_dir=out_dir,
                                          check_only=check_only,
                                          independence=independence, solver=solver)
    if not marked or result.doc is None:
        return result

    doc = dataclasses.replace(result.doc, promises=tuple(
        dataclasses.replace(p, status="unverified", reason=REVIEW_REASON)
        if p.id in marked else p
        for p in result.doc.promises))

    by_id = {p.id: p for p in doc.promises}
    report = GroundingReport(backend=result.report.backend,
                             project_root=result.report.project_root)
    for verdict in result.report.verdicts:
        if check_only and verdict.kind == "sec:artifact":
            continue  # re-decided below against the corrected bytes
        promise = by_id.get(verdict.target)
        if promise is not None and verdict.kind.startswith("sec:") and \
                verdict.target in marked:
            report.add(Verdict("unverified", verdict.kind, verdict.target,
                               verdict.lineno,
                               f"{promise.source.file}:{promise.source.line}: "
                               f"{promise.source.text!r} — {REVIEW_REASON}"))
            continue
        report.add(verdict)

    target = sec_compile._target_path(path, out_dir)
    text = sec_artifact.dumps(doc)
    if not check_only:
        sec_artifact.atomic_write(target, text)
        return sec_compile.CompileResult(doc=doc, report=report,
                                         written=os.fspath(target), drifted=False)

    on_disk = None
    if os.path.exists(target):
        try:
            with open(target, encoding="utf-8") as fh:
                on_disk = fh.read()
        except OSError as exc:
            logger.warning("cannot read committed artifact %s: %s", target, exc)
    drifted = on_disk != text
    if drifted:
        report.add(Verdict(
            "contradicted", "sec:artifact", os.fspath(target), 0,
            "the committed artifact does not match a fresh compile of its source — "
            "re-run compile-requirements and commit the result"))
    return sec_compile.CompileResult(doc=doc, report=report, written="", drifted=drifted)
