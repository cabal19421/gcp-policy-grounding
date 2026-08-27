"""The third leg of the evidence channel: an AST lint that keeps authors inside it.

:mod:`gcp_grounding.evidence` gives a domain author a sanctioned way to read a
collection, and the invokers enforce a floor on what a grounded verdict may
stand on. Neither stops the next author from writing ``doc.get("rules", [])``
and folding zero records into "every packet decided identically". This module
walks the ``ast`` of every domain file and FAILS on the shapes that produced
every reproduced instance of that defect:

``get-or-empty``
    ``X.get(k) or <empty literal>`` — the raw read is truth-tested and an
    unreadable value is laundered into "no records".
``get-default-consumed``
    ``X.get(k, <empty literal>)`` iterated or truth-tested — same laundering,
    spelled as a default.
``bare-get-iterated``
    a ``for`` / comprehension iterable that is a bare ``.get`` call — an absent
    key crashes, a wrong-typed one iterates something that is not records.
``laundering-helper``
    a helper that returns an empty result for a non-container input, whose
    result is iterated at the call site — the same substitution, one frame away,
    which is where it actually hides.

A ``.get`` compared to a scalar, or handed to ``isinstance``, is NOT a finding:
the target is iteration and truth-testing. ``gcp_grounding/core/`` is vendored
and is never walked; test modules are never walked.

The lint is falsifiable in both directions: :func:`test_lint_reports_every_forbidden_shape`
runs it over a synthetic source string carrying each shape, and
:func:`test_lint_is_silent_on_the_sanctioned_form` runs it over the
``evidence.rows`` spelling and asserts silence.

TEST-FAILS-FIRST. Run against the tree as it stands with ``ALLOWLIST = ()``,
``test_no_raw_collection_reads_outside_the_evidence_channel`` FAILED on::

    $ .venv/bin/python -m pytest -q tests/test_gcp_evidence_lint.py
    E  AssertionError: 11 raw collection read(s) outside the evidence channel.
    E    gcp_grounding/fw_claims.py:286  [get-default-consumed] normalized.get("source_tags", ())
    E    gcp_grounding/fw_claims.py:290  [get-default-consumed] normalized.get(field, ())
    E    gcp_grounding/fw_claims.py:310  [get-or-empty]         normalized.get("name") or ""
    E    gcp_grounding/sec_domains.py:236 [laundering-helper]   _iterable(values)
    E    gcp_grounding/sec_domains.py:254 [laundering-helper]   _iterable(values)
    E    gcp_grounding/sec_domains.py:260 [laundering-helper]   _iterable(entries)
    E    gcp_grounding/sec_domains.py:314 [laundering-helper]   _iterable(ports)
    E    gcp_grounding/sec_domains.py:451 [laundering-helper]   _iterable(record.get("rules"))
    E    gcp_grounding/sec_domains.py:523 [laundering-helper]   _iterable(block.get(source))
    E    gcp_grounding/tf_claims.py:136  [laundering-helper]    _module_resources(planned.get("root_module"))
    E    gcp_grounding/tf_claims.py:165  [laundering-helper]    _module_resources(child)

That list is the evidence the lint has teeth, and ``sec_domains.py:451`` is the
measured defect this whole document exists for: an absent or wrong-typed
``rules`` key becomes ``()``, and the fold then reports that the 3-level order
decides every packet identically, having read rules from zero levels.

Each site is now carried by :data:`tests.evidence_allowlist.ALLOWLIST` with a
justification, because the repairs belong to the domain tasks that own those
files and all of them land after this one. :data:`PINNED_MAX` pins the count so
it can only fall as they do, and
``test_every_allowlist_entry_still_matches_a_real_site`` makes a repaired site's
entry a failure rather than a permanent hole.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.evidence_allowlist import ALLOWLIST, Allowed

REPO_ROOT = Path(__file__).resolve().parent.parent

#: ``*_claims.py`` does NOT match ``claims.py`` — which is where two of the
#: measured proposal-tier vacuities live — so the named modules below are not
#: redundant with the globs. ``gcp_grounding/core/`` is vendored: the globs are
#: deliberately non-recursive so it can never be walked.
DOMAIN_GLOBS = ("gcp_grounding/*_checks.py", "gcp_grounding/*_claims.py")
NAMED_MODULES = (
    "gcp_grounding/claims.py",
    # org_effective.py matches neither glob (*_checks.py / *_claims.py), so it
    # is named explicitly — the effective-state fold reads estate collections
    # and must stay inside the evidence channel like every domain module.
    "gcp_grounding/org_effective.py",
    "gcp_grounding/sec_domains.py",
    "gcp_grounding/tf_claims.py",
)

#: The walk asserted against an explicit set, so a future domain file cannot be
#: silently outside it: a new ``armor_checks.py`` makes THIS fail until someone
#: adds it here, having first read what the lint is for.
EXPECTED_MODULES = frozenset({
    # armor_checks.py and armor_claims.py are the very files the comment above
    # names: they landed with agent/sx-armor-checks and agent/sx-armor-claims and
    # are now WALKED. fw_checks.py likewise (agent/sx-fw-checks).
    "gcp_grounding/armor_checks.py",
    "gcp_grounding/armor_claims.py",
    "gcp_grounding/claims.py",
    "gcp_grounding/fw_checks.py",
    "gcp_grounding/fw_claims.py",
    "gcp_grounding/hfw_checks.py",
    "gcp_grounding/hfw_claims.py",
    "gcp_grounding/iam_checks.py",
    # iam_deny_checks.py landed with the allow-x-deny interaction family and
    # is WALKED like every other *_checks.py domain module.
    "gcp_grounding/iam_deny_checks.py",
    "gcp_grounding/org_checks.py",
    # org_effective.py landed with the effective org-policy fold and is
    # WALKED by name (the globs miss it, exactly like claims.py).
    "gcp_grounding/org_effective.py",
    "gcp_grounding/sec_domains.py",
    "gcp_grounding/tf_claims.py",
    # tf_schema_checks.py landed with the provider-schema capability and is
    # WALKED like every other *_checks.py domain module.
    "gcp_grounding/tf_schema_checks.py",
    "gcp_grounding/vpcsc_claims.py",
    "gcp_grounding/vpcsc_checks.py",
})

#: The measured inventory at the moment the lint landed. The allowlist may only
#: SHRINK; raising this number is a review failure.
PINNED_MAX = 11


# -- the forbidden shapes -----------------------------------------------------

#: shape id → the sanctioned replacement, named in the failure message because
#: this lint fires on authors who have never read the design document.
REMEDIES = {
    "get-or-empty":
        "read the collection with evidence.rows(container, key, what=...) and let "
        "NotEvaluated propagate — for a single field use evidence.scalar(..., "
        "type=str, absent=...) — instead of substituting an empty literal for a "
        "value that was never read",
    "get-default-consumed":
        "drop the default and read with evidence.rows(container, key, what=...), "
        "or evidence.scalar(container, key, what=..., type=...) for one field; an "
        "empty default cannot be told apart from a collection that was observed "
        "empty, so raise NotEvaluated instead",
    "bare-get-iterated":
        "iterate evidence.rows(container, key, what=...), which returns records "
        "only for a present list and otherwise raises NotEvaluated naming the "
        "shape it got",
    "laundering-helper":
        "have the helper read through evidence.rows(container, key, what=...) — or "
        "raise an explicit NotEvaluated — rather than return an empty result for an "
        "input it could not read; evidence.scalar covers the single-field case",
}

#: Builtins that consume an iterable, mapped to the argument positions consumed.
#: Marking these makes ``for i, t in enumerate(d.get(k, ())):`` a finding on the
#: ``.get``, not on ``enumerate``.
_ITERATING_CALLS = {
    "enumerate": slice(0, 1), "sorted": slice(0, 1), "reversed": slice(0, 1),
    "list": slice(0, 1), "tuple": slice(0, 1), "set": slice(0, 1),
    "frozenset": slice(0, 1), "iter": slice(0, 1), "any": slice(0, 1),
    "all": slice(0, 1), "sum": slice(0, 1), "min": slice(0, 1),
    "max": slice(0, 1), "dict": slice(0, 1), "zip": slice(0, None),
    "map": slice(1, None), "filter": slice(1, None),
}

#: Container types a laundering helper discriminates on before returning empty.
_CONTAINER_TYPES = frozenset({
    "list", "tuple", "set", "frozenset", "dict", "Mapping", "MutableMapping",
    "Sequence", "Iterable", "Collection",
})


@dataclass(frozen=True)
class Violation:
    """One raw collection read, anchored the way an allowlist entry is."""

    module: str
    line: int
    shape: str
    segment: str

    @property
    def site(self) -> tuple[str, int, str]:
        return (self.module, self.line, self.segment)

    def __str__(self) -> str:
        return (f"{self.module}:{self.line} [{self.shape}] {self.segment}\n"
                f"      sanctioned replacement: {REMEDIES[self.shape]}")


def _name(node: ast.AST) -> str | None:
    """The dotted-tail name of a callee, so ``x.get`` reads as ``get``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_mapping_read(node: ast.AST) -> bool:
    """``X.get(k)`` or ``X.get(k, d)`` — a Mapping read whose result is raw."""
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and 1 <= len(node.args) <= 2
            and not node.keywords)


def _is_empty_literal(node: ast.AST) -> bool:
    """``[]``, ``()``, ``{}``, ``""``, ``b""``, ``list()``, ``set()``, ..."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    if isinstance(node, ast.Constant):
        return node.value in ("", b"") and isinstance(node.value, (str, bytes))
    if isinstance(node, ast.Call) and not node.args and not node.keywords:
        return _name(node.func) in ("list", "tuple", "set", "frozenset", "dict")
    return False


def _own_nodes(fn: ast.AST):
    """Every node of *fn*'s own body, stopping at a nested function or lambda —
    an inner ``extract`` closure's returns are not its factory's returns."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                             ast.ClassDef)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _iterated_and_truth_tested(tree: ast.AST) -> tuple[set, set]:
    """The expression nodes this module ITERATES, and the ones it TRUTH-TESTS.

    Both are computed by seeding the syntactic positions that consume a value
    that way and then propagating through the constructs that pass a value
    straight through — ``enumerate(...)``, a ternary, an ``or`` chain — so the
    read at the bottom is what gets named, not the wrapper around it.
    """
    iter_seeds: list[ast.AST] = []
    bool_seeds: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor)):
            iter_seeds.append(node.iter)
        elif isinstance(node, ast.comprehension):
            iter_seeds.append(node.iter)
            bool_seeds.extend(node.ifs)
        elif isinstance(node, ast.Starred):
            iter_seeds.append(node.value)
        elif isinstance(node, ast.YieldFrom):
            iter_seeds.append(node.value)
        elif isinstance(node, ast.Compare):
            if any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
                iter_seeds.extend(node.comparators)
        elif isinstance(node, ast.Call):
            consumed = (_ITERATING_CALLS.get(node.func.id)
                        if isinstance(node.func, ast.Name) else None)
            if consumed is not None:
                iter_seeds.extend(node.args[consumed])
            elif _name(node.func) == "bool":
                bool_seeds.extend(node.args)
        elif isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            bool_seeds.append(node.test)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            bool_seeds.append(node.operand)
        elif isinstance(node, ast.BoolOp):
            # every operand but the last is truth-tested for its own sake; the
            # last one only inherits whatever context the BoolOp itself is in.
            bool_seeds.extend(node.values[:-1])

    def close(seeds: list[ast.AST]) -> set:
        marked: set = set()
        while seeds:
            node = seeds.pop()
            if node in marked:
                continue
            marked.add(node)
            if isinstance(node, ast.IfExp):
                seeds.extend((node.body, node.orelse))
            elif isinstance(node, ast.BoolOp):
                seeds.extend(node.values)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                consumed = _ITERATING_CALLS.get(node.func.id)
                if consumed is not None:
                    seeds.extend(node.args[consumed])
        return marked

    return close(iter_seeds), close(bool_seeds)


def _laundering_helpers(tree: ast.AST) -> set[str]:
    """Helpers that turn an input they could not read into "no records".

    Qualifying shape: the body discriminates one of the function's own
    parameters against a container type, and some path produces an EMPTY result
    — an empty literal ``return``, or (for a generator) a bare ``return`` that
    yields nothing. That is exactly ``_iterable`` / ``_str_list`` /
    ``_module_resources``: the substitution moved one frame away from the caller
    that iterates it.
    """
    helpers: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        spec = node.args
        params = {arg.arg for arg in (*spec.posonlyargs, *spec.args,
                                      *spec.kwonlyargs)}
        own = list(_own_nodes(node))
        guarded = any(
            isinstance(n, ast.Call) and _name(n.func) == "isinstance"
            and len(n.args) == 2 and isinstance(n.args[0], ast.Name)
            and n.args[0].id in params
            and any(_name(t) in _CONTAINER_TYPES
                    for t in (n.args[1].elts if isinstance(n.args[1], ast.Tuple)
                              else [n.args[1]]))
            for n in own)
        if not guarded:
            continue
        generator = any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in own)
        empties = any(
            isinstance(n, ast.Return)
            and (_is_empty_literal(n.value) if n.value is not None else generator)
            for n in own)
        if empties:
            helpers.add(node.name)
    return helpers


def _fallen_back_to_empty(tree: ast.AST) -> dict:
    """Left-hand operand of ``... or <empty literal>`` → the whole ``or``.

    The finding is reported against the whole expression: ``doc.get("rules")``
    on its own is not the defect, and an author shown only that half would not
    see what the lint is objecting to.
    """
    marked: dict = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or)):
            continue
        for i, value in enumerate(node.values[:-1]):
            if any(_is_empty_literal(v) for v in node.values[i + 1:]):
                marked.setdefault(value, node)
    return marked


def _exempt_nodes(tree: ast.AST) -> set:
    """Reads the design explicitly spares: compared to a scalar, or handed to
    ``isinstance``. The target is iteration and truth-testing, not every read."""
    spared: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            if not any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
                spared.add(node.left)
                spared.update(node.comparators)
        elif isinstance(node, ast.Call) and _name(node.func) == "isinstance":
            spared.update(node.args)
    return spared


def lint_tree(tree: ast.AST, source: str, module: str) -> list[Violation]:
    """Every forbidden shape in an already-parsed module, in source order."""
    iterated, truth_tested = _iterated_and_truth_tested(tree)
    helpers = _laundering_helpers(tree)
    fallbacks = _fallen_back_to_empty(tree)
    exempt = _exempt_nodes(tree)
    found: list[Violation] = []

    def report(node: ast.AST, shape: str) -> None:
        segment = ast.get_source_segment(source, node) or ast.dump(node)
        found.append(Violation(module, node.lineno, shape,
                               " ".join(segment.split())))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node in exempt:
            continue
        if _is_mapping_read(node):
            default = node.args[1] if len(node.args) == 2 else None
            if node in fallbacks:
                report(fallbacks[node], "get-or-empty")
            elif default is not None and _is_empty_literal(default):
                if node in iterated or node in truth_tested:
                    report(node, "get-default-consumed")
            elif default is None and node in iterated:
                report(node, "bare-get-iterated")
        elif (isinstance(node.func, ast.Name) and node.func.id in helpers
                and node in iterated):
            report(node, "laundering-helper")

    return sorted(found, key=lambda v: (v.line, v.shape, v.segment))


def lint_source(source: str, module: str) -> list[Violation]:
    """Parse *source* and lint it — the whole-file entry point."""
    return lint_tree(ast.parse(source), source, module)


# -- the walk -----------------------------------------------------------------


def linted_modules() -> list[str]:
    """The repo-relative domain modules the lint walks, resolved from disk."""
    found = {path.relative_to(REPO_ROOT).as_posix()
             for glob in DOMAIN_GLOBS for path in REPO_ROOT.glob(glob)}
    found.update(NAMED_MODULES)
    return sorted(found)


def lint_repo() -> list[Violation]:
    found: list[Violation] = []
    for module in linted_modules():
        source = (REPO_ROOT / module).read_text(encoding="utf-8")
        found.extend(lint_source(source, module))
    return found


# -- the walk covers every domain module --------------------------------------


def test_named_modules_exist_on_disk():
    """A typo in NAMED_MODULES would silently narrow the walk to the globs."""
    for module in NAMED_MODULES:
        assert (REPO_ROOT / module).is_file(), f"{module} is not on disk"


def test_resolved_module_list_matches_the_expected_set():
    """The list itself is asserted, so a future domain file cannot be silently
    outside the walk: adding ``armor_checks.py`` fails here until it is named."""
    assert set(linted_modules()) == EXPECTED_MODULES


def test_claims_py_is_walked_although_the_globs_miss_it():
    """``*_claims.py`` does not match ``claims.py`` — which is why it is named
    explicitly, and why dropping the name would silently unwatch it."""
    by_glob = {path.relative_to(REPO_ROOT).as_posix()
               for glob in DOMAIN_GLOBS for path in REPO_ROOT.glob(glob)}
    assert "gcp_grounding/claims.py" not in by_glob
    assert "gcp_grounding/claims.py" in linted_modules()


def test_vendored_core_and_test_modules_are_never_walked():
    """``gcp_grounding/core/`` is vendored and MUST NOT be edited, so linting it
    could only produce findings nobody is allowed to fix."""
    assert list((REPO_ROOT / "gcp_grounding" / "core").glob("*.py")), \
        "core/ is empty — the exclusion below would prove nothing"
    for module in linted_modules():
        assert not module.startswith("gcp_grounding/core/"), module
        assert not module.startswith("tests/"), module


# -- the lint has teeth -------------------------------------------------------


FORBIDDEN_FIXTURE = '''
from typing import Any


def _iterable(value: Any) -> tuple:
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return ()


def or_empty(doc):
    return doc.get("rules") or []


def get_default_iterated(doc):
    for rule in doc.get("rules", []):
        yield rule


def get_default_truth_tested(doc):
    if doc.get("rules", ()):
        return "decided"
    return "vacuous"


def bare_get_iterated(doc):
    return [r for r in doc.get("rules")]


def bare_get_iterated_through_enumerate(doc):
    for i, rule in enumerate(doc.get("rules")):
        yield i, rule


def helper_result_iterated(record):
    for rule in _iterable(record.get("rules")):
        yield rule
'''

SANCTIONED_FIXTURE = '''
from gcp_grounding import evidence


def read_rules(policy, name):
    for rule in evidence.rows(policy, "rules", what=f"policy {name!r}"):
        yield rule


def read_scalar(policy, name):
    return evidence.scalar(policy, "action", what=f"policy {name!r}", type=str)


def compared_to_a_scalar(doc):
    if doc.get("mode") != "managed":
        return None
    return doc.get("kind") == "compute#firewall"


def handed_to_isinstance(doc):
    if not isinstance(doc.get("rules"), list):
        raise evidence.NotEvaluated("policy", "has no readable 'rules' list")
    return evidence.rows(doc, "rules", what="policy")


def abstains_explicitly(doc):
    if "rules" not in doc:
        raise evidence.NotEvaluated("policy", "has no 'rules' key")
    return doc["rules"]
'''


def test_lint_reports_every_forbidden_shape():
    """The positive fixture: without this, the lint could report nothing and
    every green run below would be vacuous."""
    tree = ast.parse(FORBIDDEN_FIXTURE)
    found = lint_tree(tree, FORBIDDEN_FIXTURE, "synthetic/forbidden.py")
    assert {v.shape for v in found} == {
        "get-or-empty", "get-default-consumed", "bare-get-iterated",
        "laundering-helper"}
    assert [v.segment for v in found] == [
        'doc.get("rules") or []',
        'doc.get("rules", [])',
        'doc.get("rules", ())',
        'doc.get("rules")',
        'doc.get("rules")',
        '_iterable(record.get("rules"))',
    ]


@pytest.mark.parametrize("shape", sorted(REMEDIES))
def test_each_forbidden_shape_is_reachable_from_the_positive_fixture(shape):
    """Every shape the lint claims to detect is exercised — a shape with no
    fixture is a branch nobody has run."""
    found = lint_source(FORBIDDEN_FIXTURE, "synthetic/forbidden.py")
    assert shape in {v.shape for v in found}


def test_lint_is_silent_on_the_sanctioned_form():
    """The negative fixture: a lint that fires on ``evidence.rows`` would be
    routed around within a week."""
    tree = ast.parse(SANCTIONED_FIXTURE)
    assert lint_tree(tree, SANCTIONED_FIXTURE, "synthetic/sanctioned.py") == []


def test_a_read_compared_to_a_scalar_or_isinstance_checked_is_not_a_finding():
    """Spelled out because it is the boundary the design draws: the target is
    iteration and truth-testing, not every ``.get``."""
    source = ('def f(doc):\n'
              '    if doc.get("mode") == "managed" and isinstance(doc.get("v"), list):\n'
              '        return doc.get("count", 0) > 0\n'
              '    return None\n')
    assert lint_source(source, "synthetic/spared.py") == []


def test_a_violation_names_file_line_segment_and_the_replacement():
    """The message is the whole interface for an author who has never read the
    design, so it must carry all four."""
    found = lint_source('def f(doc):\n    return doc.get("rules") or []\n',
                        "synthetic/one.py")
    assert len(found) == 1
    rendered = str(found[0])
    assert "synthetic/one.py" in rendered
    assert ":2" in rendered
    assert 'doc.get("rules") or []' in rendered
    assert "evidence.rows" in rendered
    assert "evidence.scalar" in rendered
    assert "NotEvaluated" in rendered


@pytest.mark.parametrize("shape", sorted(REMEDIES))
def test_every_shape_names_a_sanctioned_replacement(shape):
    """No shape may report "this is wrong" without saying what to write."""
    assert any(outlet in REMEDIES[shape]
               for outlet in ("evidence.rows", "evidence.scalar",
                              "NotEvaluated")), shape


# -- the tree, and the allowlist ----------------------------------------------


def _render(violations) -> str:
    return "\n".join(f"  {v}" for v in violations)


def test_no_raw_collection_reads_outside_the_evidence_channel():
    allowed = {entry.site for entry in ALLOWLIST}
    outstanding = [v for v in lint_repo() if v.site not in allowed]
    assert not outstanding, (
        f"{len(outstanding)} raw collection read(s) outside the evidence "
        "channel. A Mapping read whose raw result is iterated or truth-tested "
        "turns UNREADABLE and NEVER LOOKED into NO RECORDS, and no records "
        "reads as agreement. Route each through gcp_grounding.evidence — "
        "evidence.rows for a collection, evidence.scalar for one field — or "
        "raise an explicit NotEvaluated:\n" + _render(outstanding))


def test_allowlist_entry_count_is_pinned_and_may_only_shrink():
    assert len(ALLOWLIST) <= PINNED_MAX, (
        f"the evidence allowlist has grown to {len(ALLOWLIST)} entries against a "
        f"pin of {PINNED_MAX}. It may only shrink: fix the site or escalate — "
        "raising PINNED_MAX is a review failure.")


def test_every_allowlist_entry_still_matches_a_real_site():
    """A stale entry is a FAILURE, not a permanent hole: once the owning domain
    task repairs a site, the entry that covered it must be deleted."""
    sites = {v.site for v in lint_repo()}
    stale = [entry for entry in ALLOWLIST if entry.site not in sites]
    assert not stale, (
        "these evidence-allowlist entries no longer match a site the lint "
        "reports — the code moved or was repaired, so delete them:\n"
        + "\n".join(f"  {e.module}:{e.line} {e.segment!r}" for e in stale))


def test_every_allowlist_entry_carries_a_justification():
    for entry in ALLOWLIST:
        assert isinstance(entry, Allowed), entry
        assert entry.justification.strip(), f"{entry.module}:{entry.line}"
        assert entry.justification.strip().endswith("."), (
            f"{entry.module}:{entry.line}: the justification is one sentence")
