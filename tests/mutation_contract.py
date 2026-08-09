"""The in-repo mutation contract: the entry type and its content anchor.

SLICE 3 -- the EXECUTION ENGINE, and NOT the flip. Its 13 manifest items
measured 24,609 diff characters of content ALONE against a binding 16,000, so
this slice lands the portion that fits and REWRITES the manifest instead of
deleting it, because items remain -- an emptied or deleted manifest here is the
green reading hollow this wave exists to correct. Under house rule 4 that is an
amendment request: the oracle's third conjunct is unmet, and so its second.
ENFORCEMENT THEREFORE STAYS INERT, A STAGING DEVICE AND NEVER AN OUTCOME: no
gate is armed or written, no register-wide assertion executes a ``Mutation``,
the register is empty and the AWAITING pin has not risen. :func:`execute` is
the engine such a gate calls, run only by this module's OWN self-tests.

MEASURED ``git diff``, which reproduces ``gitutil.diff_text`` exactly:
slice 1 15,937 characters, slice 2 15,958, slice 3 15,999.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from dataclasses import dataclass
from hashlib import sha256
from importlib import import_module
from pathlib import Path


class ContractError(AssertionError):
    """An anchor that does not resolve, or an outcome that cannot be read."""


@dataclass(frozen=True)
class Mutation:
    """One source-rewrite must-kill, anchored on CONTENT and never on a line.

    ``id`` matches its MK id in the design verbatim; ``module`` is repo-relative.
    ``enclosing`` is the qualified def/class name the site sits in, or a verbatim
    one-line snippet of a module-level statement occurring exactly once; None
    ONLY while its owner is absent, never on an entry that executes.
    ``before``/``after`` are the exact source text of the site, and an ambiguous
    ``before`` is widened over several lines -- never fixed by deleting the
    entry, by a line number, or by loosening exactly-once. ``line_hint`` is
    ADVISORY: printed in every failure, NEVER asserted. ``behaviour`` names the
    observable the mutant changes. ``must_fail`` is a tuple of EXACT pytest node
    ids. ``owner`` is the task whose body names the entry -- REQUIRED, never
    blank, the handle every AWAITING rule turns on.
    """

    id: str
    module: str
    enclosing: str | None
    before: str
    after: str
    line_hint: int
    behaviour: str
    must_fail: tuple[str, ...]
    owner: str


def _span(node: ast.AST) -> tuple[int, int]:
    """Inclusive line span, DECORATORS INCLUDED: ``ast`` puts a ClassDef's lineno
    at the ``class`` keyword, so a mutated decorator sits above the bare scope."""
    starts = [node.lineno] + [d.lineno for d in getattr(node, "decorator_list", ())]
    return min(starts), node.end_lineno or node.lineno


def _definitions(source: str) -> dict[str, list[ast.AST]]:
    """Every def/class in *source*, keyed by QUALIFIED name."""
    found: dict[str, list[ast.AST]] = {}

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                found.setdefault(prefix + child.name, []).append(child)
                walk(child, f"{prefix}{child.name}.")
            else:
                walk(child, prefix)

    walk(ast.parse(source), "")
    return found


def resolve_span(source: str, enclosing: str) -> tuple[int, int]:
    """The span the rewrite is CONFINED to: the ONE definition named *enclosing*,
    or the module-level statement carrying it as a snippet occurring exactly
    once. Ambiguity is fixed by widening, never by an index."""
    defs = _definitions(source).get(enclosing, [])
    if len(defs) > 1:
        raise ContractError(f"{enclosing!r}: {len(defs)} definitions; qualify it")
    if defs:
        return _span(defs[0])
    hits = source.count(enclosing)
    if hits != 1:
        raise ContractError(f"{enclosing!r}: defines nothing and occurs {hits} times "
                            "as a module-level snippet; widen it to one")
    line = source[: source.index(enclosing)].count("\n") + 1
    for stmt in ast.parse(source).body:
        start, end = _span(stmt)
        if start <= line <= end:
            return start, end
    return line, line


def mutate(source: str, entry: Mutation) -> tuple[str, int]:
    """Rewrite the one named site INSIDE ITS OWN SCOPE; return the new source and
    the 1-based line that changed. Confinement is load-bearing, not tidiness: a
    slice need only be unique inside its scope, so a file-level replace could
    mutate a site no entry names while every assertion still passed -- proving
    something about the wrong code and reporting it a kill."""
    if entry.enclosing is None:
        raise ContractError(f"{entry.id}: enclosing is None, so it has no anchor")
    if entry.before == entry.after:
        raise ContractError(f"{entry.id}: before == after, so nothing is mutated")
    start, end = resolve_span(source, entry.enclosing)
    lines = source.splitlines(keepends=True)
    scope = "".join(lines[start - 1 : end])
    hits = scope.count(entry.before)
    where = f"{entry.enclosing} (lines {start}-{end}, hint {entry.line_hint})"
    if hits != 1:
        raise ContractError(f"{entry.id}: `before` occurs {hits} times in {where}; "
                            "widen the slice over more lines")
    pos = scope.find(entry.before)
    mutated = ("".join(lines[: start - 1])
               + scope[:pos] + entry.after + scope[pos + len(entry.before) :]
               + "".join(lines[end:]))
    clean_lines, mutant_lines = source.splitlines(), mutated.splitlines()
    if len(clean_lines) != len(mutant_lines):
        raise ContractError(f"{entry.id}: the rewrite changed the LINE COUNT in {where}")
    changed = [i for i, (a, b) in enumerate(zip(clean_lines, mutant_lines), 1) if a != b]
    if len(changed) != 1:
        raise ContractError(f"{entry.id}: {len(changed)} lines differ, expected 1")
    if not start <= changed[0] <= end:
        raise ContractError(f"{entry.id}: changed line {changed[0]} is OUTSIDE {where}")
    return mutated, changed[0]


# -- SLICE 2. Enforcement stays INERT: nothing here executes a ``Mutation``.

#: Owner -> the FROZEN tests/spec_assertions.py entry whose REGISTERED predicate
#: IS its signal, read from there and never copied, so it stays unweakenable.
_REGISTERED = {
    "gx-preflight-empty-key": "SA-PREFLIGHT-BINDINGS-PRESENT",
    "gx-evidence-invokers": "SA-INVOKERS-ROWS-EXAMINED",
    "gx-sexpr-one-form": "SA-SEXPR-ONE-FORM",
}

#: The four AMENDMENT 3 owners carry a PRESENCE SLICE instead: (module, text).
_SLICES = {
    "gx-iam-escalation-evidence": ("gcp_grounding/iam_checks.py", "_UNDECIDED_GRANTEE"),
    "gx-org-claim-completeness": ("gcp_grounding/claims.py", "unreadable=(skipped,)"),
    "gx-hierfw-records": ("gcp_grounding/hfw_checks.py", "def _nothing_folded("),
    "gx-vpcsc-record-guards": ("gcp_grounding/vpcsc_checks.py", "def _unreadable_field("),
}

#: The only sanctioned sources; each answer's is printed in its AWAITING line.
CHECKOUT_COLLECT = "this checkout's collect-only pass"
SOURCES = (CHECKOUT_COLLECT, "collect-only over the owner's branch archive",
           "the owner task's own notes")

ACTIVE, AWAITING = "ACTIVE", "AWAITING"

#: The PINNED AWAITING MAXIMUM: the ids permitted to compute AWAITING. It may
#: only SHRINK, and never excuses a debt -- the floor outranks it, always.
AWAITING_MAX: frozenset = frozenset()

_COLLECTED: dict[str, frozenset] = {}


def owner_signals() -> dict[str, tuple[str, str]]:
    """Owner -> (module, signal text): the whole table, and its only keys."""
    from tests.spec_assertions import ASSERTIONS

    frozen = {a.id: a for a in ASSERTIONS}
    table = {o: (frozen[i].module, frozen[i].predicate) for o, i in _REGISTERED.items()}
    table.update(_SLICES)
    return table


def owner_is_present(owner: str, root, modules=()) -> bool:
    """READ THE SIGNAL FROM THE TREE, NEVER FROM A DECLARATION: present when its
    signal really is in its module under *root* and every module the owner's
    entries name exists. A missing file reads ABSENT; an unsignalled owner
    RAISES rather than defaulting to True."""
    table = owner_signals()
    if owner not in table:
        raise ContractError(f"{owner!r}: no presence signal; owners are {sorted(table)}")
    module, signal = table[owner]
    path = Path(root) / module
    if not path.is_file() or signal not in path.read_text(encoding="utf-8"):
        return False
    return all((Path(root) / m).is_file() for m in modules)


def present_owners(entries, root) -> dict[str, bool]:
    """Owner -> presence: ONE signal read per owner, never one per entry."""
    named: dict[str, set] = {}
    for entry in entries:
        named.setdefault(entry.owner, set()).add(entry.module)
    return {o: owner_is_present(o, root, mods) for o, mods in named.items()}


def strip_parametrization(node_id: str) -> str:
    """Without its ``[case]``: a parametrized case is not a missing test."""
    return node_id.partition("[")[0]


def collected_node_ids(root, label: str = "tests.mutation_contract") -> frozenset:
    """The tree's node ids, read ONCE PER SESSION per root by COLLECTION not by
    grep, counted on gx-hookrunner-budget's subprocess budget. NEVER at import
    time: collecting a tree while it is itself collected is a fork bomb."""
    key = str(Path(root).resolve())
    if key not in _COLLECTED:
        from tests.agentic.hookrunner import current_budget

        current_budget().increment(label)
        done = subprocess.run(
            [sys.executable, "-B", "-m", "pytest", "--collect-only", "-q", "tests"],
            cwd=key, capture_output=True, text=True)
        if done.returncode != 0:
            raise ContractError(f"collect-only under {key} exited {done.returncode}:\n"
                                + done.stdout[-1500:])
        _COLLECTED[key] = frozenset(strip_parametrization(line.strip())
                                    for line in done.stdout.splitlines() if "::" in line)
    return _COLLECTED[key]


def collects_in(root):
    """The ``collects(node_id) -> bool`` seam, bound to *root*'s collection."""
    ids = collected_node_ids(root)
    return lambda node_id: strip_parametrization(node_id) in ids


@dataclass(frozen=True)
class EntryState:
    """One entry's COMPUTED state -- EXACTLY TWO, never a third. ``unresolved``
    names the field that kept an AWAITING entry out of ACTIVE, ``source`` which
    sanctioned source answered its node ids; both print, so none goes quiet."""

    id: str
    owner: str
    state: str
    unresolved: str
    source: str

    def line(self) -> str:
        return (f"{self.id} owner={self.owner} {self.state} "
                f"unresolved={self.unresolved or '-'} source={self.source}")


def state_of(entry: Mutation, root, *, present, collects,
             source: str = CHECKOUT_COLLECT) -> EntryState:
    """ACTIVE when its anchor resolves AND its node ids ALL collect AND its owner
    is present; otherwise AWAITING, SHAPE-CHECKED ONLY, never executed, never
    deleted, never counted as satisfied. *present*/*collects* are the injected
    seams with NO DEFAULT THAT ANSWERS TRUE; resolving an anchor is not execution."""
    def awaiting(why: str) -> EntryState:
        return EntryState(entry.id, entry.owner, AWAITING, why, source)

    if not present(entry.owner):
        return awaiting("owner")
    absent = [node for node in entry.must_fail if not collects(node)]
    if absent:
        return awaiting(f"must_fail node id {absent[0]}")
    try:
        mutate((Path(root) / entry.module).read_text(encoding="utf-8"), entry)
    except (OSError, ContractError) as exc:
        return awaiting(f"{type(exc).__name__}: {exc}")
    return EntryState(entry.id, entry.owner, ACTIVE, "", source)


def floor_failure(states, presence) -> str:
    """THE FLOOR IS ABSOLUTE: an entry whose OWNER IS PRESENT MUST be ACTIVE.
    Empty when it holds, else the id, owner and unresolved field that broke it."""
    broken = [s for s in states if s.state == AWAITING and presence.get(s.owner)]
    return "" if not broken else ("AWAITING with the owner PRESENT, forbidden:\n"
                                  + "\n".join(s.line() for s in broken))


def awaiting_overflow(states) -> str:
    """Empty when the AWAITING set is a SUBSET of the pin, else the overflow."""
    over = sorted({s.id for s in states if s.state == AWAITING} - AWAITING_MAX)
    return "" if not over else "AWAITING beyond the pinned maximum: " + ", ".join(over)


def register() -> tuple:
    """The 65 entries are DATA belonging to seed-a and seed-b, so this READS
    tests/mutation_entries.py BY STRING -- that frozen path is on no branch yet,
    so a static import of it names nothing -- EMPTY until it lands."""
    try:
        entries = import_module("tests.mutation_entries")
    except ModuleNotFoundError:
        return ()
    return tuple(getattr(entries, "ENTRIES", ()))


# -- SLICE 3. The execution engine. NO gate is armed and none is written. ---

#: Every outcome ``-rA`` prints, and the only answers :func:`parse_outcomes`
#: returns. ONLY FAILED is ever a kill.
OUTCOMES = ("PASSED", "FAILED", "ERROR", "SKIPPED", "XFAIL", "XPASS")


def materialise(root, parent, name: str) -> Path:
    """A FRESH scratch copy PER ENTRY: ``git archive HEAD`` piped into ``tar
    -x``, so uncommitted work never leaks in, under a *parent* holding no
    discoverable state -- the copy's own pyproject.toml stops the walk."""
    dest = Path(parent) / name
    dest.mkdir(parents=True)
    archive = subprocess.run(["git", "-C", str(root), "archive", "HEAD"],
                             capture_output=True)
    if archive.returncode != 0:
        raise ContractError(f"git archive HEAD: {archive.stderr.decode()[-300:]}")
    subprocess.run(["tar", "-x", "-C", str(dest)], input=archive.stdout, check=True)
    return dest


def apply_to_copy(copy, entry: Mutation) -> int:
    """Rewrite the one named site in *copy* and PROVE it changed: the mutant's
    sha256 must differ from the clean one's, else the rewrite did nothing."""
    path = Path(copy) / entry.module
    clean = path.read_bytes()
    mutated, line = mutate(clean.decode("utf-8"), entry)
    path.write_text(mutated, encoding="utf-8")
    if sha256(path.read_bytes()).hexdigest() == sha256(clean).hexdigest():
        raise ContractError(f"{entry.id}: {entry.module} is unchanged by the rewrite")
    return line


def parse_outcomes(report: str, nodes) -> dict:
    """THE OUTCOME OF EVERY NAMED NODE, READ EXPLICITLY off ``-rA`` and typed to
    :data:`OUTCOMES`. A skip prints as ``file:line``, never as a node id, so a
    named node with a skip in its file reads SKIPPED; no outcome at all RAISES."""
    seen, skipped = {}, set()
    for raw in report.splitlines():
        head, _, rest = raw.strip().partition(" ")
        if head not in OUTCOMES or not rest:
            continue
        if head == "SKIPPED":
            bits = rest.split()
            skipped.add(bits[1 if bits[0].startswith("[") else 0].partition(":")[0])
        else:
            seen[rest.partition(" - ")[0].strip()] = head
    out = {}
    for node in nodes:
        hits = [v for k, v in seen.items()
                if k == node or strip_parametrization(k) == node]
        if hits:
            out[node] = next((h for h in hits if h != "FAILED"), "FAILED")
        elif node.partition("::")[0] in skipped:
            out[node] = "SKIPPED"
        else:
            raise ContractError(f"{node}: -rA printed NO outcome; it never ran")
    return out


def run_nodes(copy, nodes) -> dict:
    """``python -B -m pytest -q -rA <the must_fail node ids>``, *copy* as cwd,
    counted on gx-hookrunner-budget's subprocess budget."""
    from tests.agentic.hookrunner import current_budget

    current_budget().increment("tests.mutation_contract.run_nodes")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    done = subprocess.run([sys.executable, "-B", "-m", "pytest", "-q", "-rA", *nodes],
                          cwd=str(copy), capture_output=True, text=True, env=env)
    return parse_outcomes(done.stdout, nodes)


def kill_failure(entry, outcomes) -> str:
    """ONLY FAILED SATISFIES A ``must_fail``, and an EMPTY ``must_fail`` is
    refused BEFORE ANY OUTCOME IS READ: a witness-less entry never reads green."""
    if not entry.must_fail:
        return f"{entry.id}: must_fail is EMPTY, so no node can witness the kill"
    lived = sorted(f"{n}={outcomes.get(n, 'MISSING')}" for n in entry.must_fail
                   if outcomes.get(n) != "FAILED")
    if lived and "SKIPPED" in outcomes.values():
        lived.append("a SKIPPED node means the removal reached the tree BEFORE "
                     "collection -- the ordering inversion, and never a kill")
    return "" if not lived else f"{entry.id}: SURVIVED -- " + ", ".join(lived)


def execute(entry: Mutation, root, parent) -> str:
    """Materialise, ASSERT THE UNMUTATED COPY GREEN, then mutate and re-run: an
    outcome read off a copy that was already red proves nothing about a mutant."""
    if not entry.must_fail:
        return kill_failure(entry, {})
    copy = materialise(root, parent, entry.id)
    red = sorted(n for n, got in run_nodes(copy, entry.must_fail).items()
                 if got != "PASSED")
    if red:
        raise ContractError(f"{entry.id}: the UNMUTATED copy is not green: {red}")
    apply_to_copy(copy, entry)
    return kill_failure(entry, run_nodes(copy, entry.must_fail))
