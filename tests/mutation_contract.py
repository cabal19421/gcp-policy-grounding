"""The in-repo mutation contract: the entry type and its content anchor.

SLICE 1 OF 3 -- the portion every later item calls. What remains is enumerated,
per obligation, in tests/mutation_contract_manifest.json: slice 2's only work
order, where an item left out is an obligation silently deleted.

ENFORCEMENT IS INERT HERE, AS A STAGING DEVICE AND NEVER AS AN OUTCOME: nothing
executes a ``Mutation``, no gate is armed and no register is read. Slice 3 flips
it live; arming one arm and leaving another unwritten would be the HALF-ARMED
GATE no slice may produce. There are EXACTLY TWO STATES when it does -- AWAITING
and ACTIVE, never a third -- and :func:`mutate` RAISES rather than reporting, so
the slice-2 caller computing the state, over signals INJECTED with NO default
that answers True, can never read an unresolved anchor as a resolved one.

MEASURED DIFF: 15,937 characters under ``gitutil.diff_text`` (``git diff``
reproduces it), against the 16,000 the slice protocol makes binding.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass


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
