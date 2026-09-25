"""The regression net for the documentation rows of the 2026-09-25 audit —
R13, R14, R16-R23, R34-R39 and R52-R56.

Every one of these rows is a sentence, a count or a quoted block that was true
once. None of them was pinned by anything, which is why all of them rotted. So
each test below re-derives the claim from the thing it describes rather than
from a second copy of the text:

* the COUNTS (R17, R19, R20, R53) are recomputed from the table each sentence is
  about — ``PROVIDER_MODULES``, ``identity.SPECS``, ``sec_domains.COLLECTION_SPECS``
  and the record categories with no ``baseline`` projection — so the next module
  added to any of them reddens the sentence instead of ageing it unnoticed;
* the ATTRIBUTE PATHS (R21, R22, R39) are pinned from both sides: the spelling
  the docstrings now use resolves, and the spelling they used before still
  names nothing, so the assertion is about existence and not about wording;
* the LINE ANCHORS (R23) are pinned as a closed set. Twelve of the sixteen
  ``<file>.py:<line>`` anchors in package docstrings pointed at unrelated code,
  and the row's own remedy is the symbol name, which cannot drift — so the four
  that survive are listed by hand and each is resolved against its target file.
  A new anchor fails here by design: write the symbol instead;
* the WRAPPED ROLE TARGETS (R38) are swept package-wide rather than site by
  site. A Sphinx target broken across a source line carries a newline plus
  indentation and cannot resolve, and the defect is invisible to every other
  check in the suite;
* the QUOTED BLOCKS (R16, R34, R35, R36, R37) are compared against a real
  render or a real run. R16's drill-down is checked field-label by field-label
  against ``explain_state.fact_lines``; R34's and R35's elisions are checked
  against the listings the two scenarios actually print; R37's promise block is
  compared byte for byte with the committed corpus file;
* the PRECONDITION (R13) is pinned behaviourally as well as textually: a
  ``.tf.json`` proposal with ``--snapshot`` alone really does exit 0 having
  checked nothing, and both pages have to say so;
* the AUTHORING GUIDE (R17, R18, R52, R54) is pinned against the parser and the
  registry it documents — its collection table equals the root page's and both
  equal ``sec_ast.COLLECTIONS``, its module names are files, and the corpora it
  sends a reader to are corpora ``sec_parse.discover`` finds.

R56 needs no test: its finding is that five arcs run commands documented in
prose rather than in a fenced block, and the audit's verdict was "None needed;
recorded as coverage".

Everything is in-process — no subprocess, so no spawn budget is touched. Two
tests need a solver, because a promise verdict is what they read; they are
skipped rather than branched, since a check listing with no ``sec:`` line is a
different listing and pinning it would pin the wrong thing.
"""

from __future__ import annotations

import ast
import importlib
import re
from pathlib import Path

import pytest

from gcp_grounding import (
    baseline,
    engine,
    explain_state,
    facts,
    iam_deny_checks,
    identity,
    knowledge,
    provenance,
    registry,
    sec_ast,
    sec_domains,
    sec_parse,
    sources,
)
from gcp_grounding.cli import main
from gcp_grounding.core.report import GroundingReport
from gcp_grounding.core.solver import get_solver

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = REPO_ROOT / "gcp_grounding"
README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
SIMPLE = (REPO_ROOT / "simple_readme.md").read_text(encoding="utf-8")
AUTHORING = (REPO_ROOT / "sec_requirements" / "README.md").read_text(encoding="utf-8")
RUN_DEMO = (REPO_ROOT / "run_demo.sh").read_text(encoding="utf-8")

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
AGENTIC_SNAPSHOT = FIXTURES / "agentic_snapshot.json"

MASKED = REPO_ROOT / "examples" / "terraform-masked"
DENYPOLICY = REPO_ROOT / "examples" / "terraform-denypolicy"
ORGPOLICY = REPO_ROOT / "examples" / "terraform-orgpolicy"
WALKTHROUGH = REPO_ROOT / "examples" / "walkthrough"

HAVE_Z3 = get_solver().backend == "z3"
_needs_z3 = pytest.mark.skipif(
    not HAVE_Z3, reason="no z3: the promise verdicts these listings quote "
                        "abstain on the builtin backend, so the listing the "
                        "README quotes is not the listing that prints")

#: A Sphinx cross-reference role and its target, target group 1.
ROLE = re.compile(r":(?:mod|data|class|func|attr|meth|exc|obj|const):`([^`]*)`", re.S)

#: A ``<file>.py:<lo>`` or ``<file>.py:<lo>-<hi>`` anchor inside a docstring.
ANCHOR = re.compile(
    r"\b([A-Za-z_][\w]*(?:/[A-Za-z_][\w]*)*\.py):(\d+)(?:-(\d+))?")

#: The four anchors the audit measured ACCURATE, with what each one names. Every
#: other anchor was replaced by its symbol name (R23), so this set is closed:
#: ``target file -> (lo, hi, a string the anchored lines must contain)``.
SURVIVING_ANCHORS = {
    ("gcp_grounding/sec_encode.py", "core/solver.py:105"):
        ("gcp_grounding/core/solver.py", 105, 105, "def get_solver("),
    ("gcp_grounding/sec_encode.py", "constraints.py:303-310"):
        ("gcp_grounding/constraints.py", 303, 310, "def check_cel("),
    ("gcp_grounding/sec_evidence.py", "core/report.py:22-29"):
        ("gcp_grounding/core/report.py", 22, 29, "class Verdict:"),
    ("gcp_grounding/sec_evidence.py", "core/__init__.py:5-7"):
        ("gcp_grounding/core/__init__.py", 5, 7, "re-vendor"),
}

NUMBER_WORDS = {
    2: "two", 4: "four", 6: "six", 8: "eight", 11: "eleven", 12: "twelve",
    14: "fourteen", 15: "fifteen", 16: "sixteen", 18: "eighteen", 19: "nineteen",
}


# -- helpers ------------------------------------------------------------------


def flat(text: str) -> str:
    """*text* with every run of whitespace collapsed, so a sentence the page
    hand-wraps to its column width still compares."""
    return " ".join(text.split())


def source_of(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def docstrings(path: Path) -> list[str]:
    """Every module, class and function docstring in *path*."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                found.append(doc)
    return found


def package_files() -> list[Path]:
    return sorted(PACKAGE.rglob("*.py"))


def resolves(dotted: str) -> bool:
    """Whether *dotted* names something: the longest importable prefix, then an
    attribute walk. A dataclass field declared with no default lives only in
    ``__annotations__``, so it counts as present."""
    parts = dotted.lstrip("~").split(".")
    obj: object | None = None
    depth = 0
    for stop in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:stop]))
        except ImportError:
            continue
        depth = stop
        break
    if obj is None:
        return False
    for name in parts[depth:]:
        if hasattr(obj, name):
            obj = getattr(obj, name)
        elif name in getattr(obj, "__annotations__", {}):
            return True
        else:
            return False
    return True


def base_collection_names() -> set[str]:
    """The four names ``sec_ast`` SEEDS ``COLLECTIONS`` with, read off the literal.

    Not off the live dict: ``COLLECTIONS`` is a process-global that other test
    modules register scratch collections into, so what a documented table can be
    compared against is the seed plus the domain layer's own specs — never the
    registry's contents at some point in a shared session.
    """
    tree = ast.parse(source_of("gcp_grounding/sec_ast.py"))
    for node in ast.walk(tree):
        if (isinstance(node, ast.AnnAssign)
                and getattr(node.target, "id", "") == "COLLECTIONS"
                and isinstance(node.value, ast.Dict)):
            return {key.value for key in node.value.keys}
    raise AssertionError("sec_ast no longer seeds COLLECTIONS with a dict literal")


def registry_names() -> set[str]:
    """Every collection the shipped compiler registers: the seed plus the eleven."""
    return base_collection_names() | {spec.name
                                      for spec in sec_domains.COLLECTION_SPECS}


def collection_table(text: str) -> list[str]:
    """The rows of the 15-collection table in *text*, asserted to appear once."""
    tables = re.findall(
        r"^\| Policy surface \| Collection \| Tier \| Fields \(`name:Sort`\) \|\n"
        r"\| --- \| --- \| --- \| --- \|\n((?:\|.*\n)+)", text, re.M)
    assert len(tables) == 1, f"expected exactly one collection table, got {len(tables)}"
    return [row for row in tables[0].splitlines() if row.strip()]


def check_lines(out: str) -> list[str]:
    """The report's own ``✓`` check listing, one flattened line per verdict.

    The narrative recap above the report repeats some of them at a different
    indent, so the listing is taken from the report half — the lines indented
    exactly two spaces, which is what the README quotes with its own wrapping.
    """
    return [flat(line) for line in out.splitlines()
            if line.startswith("  ✓ [")]


def printed(listing: list[str], quoted: str) -> bool:
    """Whether some line of *listing* is *quoted* plus its provenance suffix —
    which is exactly the relaxation the page's stated convention buys (R34)."""
    return any(line == quoted or line.startswith(quoted + " [")
               for line in listing)


def two_source_drill_down(domain: str, key: str) -> list[str]:
    """A REAL ``--state-explain DOMAIN:KEY`` render over a ledger with one
    winner and one losing alternate. The README's block is hypothetical (its
    paths are an operator's, not this repo's), so what can be pinned is the
    SHAPE: which field labels the renderer emits, in what order, and that an
    alternate is always followed by its own ``record:`` line."""
    builder = provenance.LedgerBuilder()
    builder.source("estate/api-snapshot.json", "unattributed",
                   origin="estate/api-snapshot.json",
                   captured_at="2026-07-18T09:30:00Z", scope="partial")
    builder.source("infra/prod/terraform.tfstate", "tfstate",
                   origin="infra/prod/terraform.tfstate",
                   captured_at="2026-07-18T09:30:00Z", scope="partial")
    builder.declare(domain, scope="partial", source_kinds=("unattributed", "tfstate"))
    builder.fact(domain, key, source_id="estate/api-snapshot.json")
    builder.alternate(domain, key, source_id="infra/prod/terraform.tfstate",
                      locator="google_project_iam_binding.owner",
                      record={"bindings": []},
                      reason="lost to 'estate/api-snapshot.json' under precedence "
                             "'api-wins'")
    proposal = engine.prepare_proposal({"bindings": []}, "iam_policy",
                                       source="<proposal>")
    result = engine.EvaluationResult(report=GroundingReport(), proposal=proposal)
    return explain_state.fact_lines(result, builder.build(), domain, key)


@pytest.fixture(scope="module")
def masked_narrowed(tmp_path_factory):
    """README step 9d + 9e in process: the scenario's corpus compiled, then the
    narrowed remediation judged with it in force. Exit 0 — the approval R34's
    block quotes."""
    out = tmp_path_factory.mktemp("compiled-masked")
    assert main(["compile-requirements", str(MASKED), "--snapshot",
                 str(AGENTIC_SNAPSHOT), "--out", str(out)]) == 0
    return out


# -- R17, R19, R20, R53: a count is recomputed, never quoted -------------------


@pytest.mark.parametrize("relative,phrase,measure", [
    # R19 — registry.py said "the twelve later grounding-domain modules".
    ("gcp_grounding/registry.py", "the {} later grounding-domain modules",
     lambda: len(registry.PROVIDER_MODULES)),
    # R20 — compare.py said "eighteen category specs".
    ("gcp_grounding/compare.py", "{} category specs",
     lambda: len(identity.SPECS)),
    # R17 — sec_ast.py said "the six domain sections", twice.
    ("gcp_grounding/sec_ast.py", "extended by the {} domain sections",
     lambda: len(sec_domains.COLLECTION_SPECS)),
    ("gcp_grounding/sec_ast.py", "The {} domain collections would exist",
     lambda: len(sec_domains.COLLECTION_SPECS)),
    # R53 — baseline.py said "The five categories with no entry", a number no
    # category set in the tree yields; its own two examples are the two.
    ("gcp_grounding/baseline.py", "The {} record categories with no",
     lambda: len(set(facts.TABLE_CATEGORIES) - set(baseline._PROJECTIONS))),
])
def test_a_counted_claim_matches_the_table_it_counts(relative, phrase, measure):
    measured = measure()
    word = NUMBER_WORDS[measured]
    assert flat(phrase.format(word)) in flat(source_of(relative)), (
        f"{relative} does not say {word!r} where it counts {measured}")


def test_the_eleven_domain_collections_are_the_ones_the_registrar_adds():
    """The count above is only meaningful while the registrar is what supplies
    it: four base entries, eleven more from the domain layer, fifteen in all."""
    sec_domains.register()
    base = base_collection_names()
    domain = {spec.name for spec in sec_domains.COLLECTION_SPECS}
    assert len(base) == 4 and len(domain) == 11 and base.isdisjoint(domain)
    assert len(base | domain) == 15
    assert (base | domain) <= set(sec_ast.COLLECTIONS), \
        "the registrar no longer installs what it declares"


# -- R21, R22, R39: an attribute path names a real attribute -------------------


@pytest.mark.parametrize("stale,live,holder,attribute", [
    # R21 — cli.py named sources.SourceOptions.from_env; from_env is a module
    # function, and the behavioural claim around it was always correct.
    ("sources.SourceOptions.from_env", "sources.from_env",
     sources.SourceOptions, "from_env"),
    # R22 — preflight.py and engine.py named registry.PAIR_CHECKS; the tables
    # are the providers' and registry reads them through pair_check().
    ("registry.PAIR_CHECKS", "registry.pair_check", registry, "PAIR_CHECKS"),
    # R39 — estate.py named knowledge.network_tag_exists; it is a method.
    ("knowledge.network_tag_exists", "knowledge.GcpSnapshot.network_tag_exists",
     knowledge, "network_tag_exists"),
])
def test_no_docstring_names_an_attribute_path_that_resolves_to_nothing(
        stale, live, holder, attribute):
    assert not hasattr(holder, attribute), (
        f"{stale} exists now, so this row's premise changed and the pin needs "
        f"re-reading rather than the docstrings")
    assert resolves(f"gcp_grounding.{live}"), live
    naming = [str(path.relative_to(REPO_ROOT)) for path in package_files()
              if any(stale in doc for doc in docstrings(path))]
    assert naming == [], f"{stale} still named in: {naming}"


def test_every_surviving_docstring_line_anchor_points_where_it_says():
    """R23. The ``file:line`` form drifts on every edit above it, so twelve of
    the sixteen anchors were replaced by the symbol name. These four were
    measured accurate and are kept as the closed set — a new one fails here
    deliberately, because the symbol name is the form that cannot rot."""
    found = {}
    for path in package_files():
        relative = str(path.relative_to(REPO_ROOT))
        for doc in docstrings(path):
            for match in ANCHOR.finditer(doc):
                found[(relative, match.group(0))] = match

    assert set(found) == set(SURVIVING_ANCHORS), (
        f"unexpected: {sorted(set(found) - set(SURVIVING_ANCHORS))}; "
        f"missing: {sorted(set(SURVIVING_ANCHORS) - set(found))}")

    for site, (target, lo, hi, needle) in SURVIVING_ANCHORS.items():
        lines = source_of(target).splitlines()
        window = "\n".join(lines[lo - 1:hi])
        assert needle in window, f"{site}: {target}:{lo}-{hi} no longer holds {needle!r}"


def test_no_sphinx_role_target_is_broken_across_a_source_line():
    """R38. A target carrying a newline plus indentation cannot resolve as a
    reference, and no other check in the suite can see it. Swept over the whole
    package, comments included: the audit's own walk read docstrings only, which
    is why it counted eleven sites where the tree held twelve."""
    wrapped = []
    for path in package_files():
        text = path.read_text(encoding="utf-8")
        for match in ROLE.finditer(text):
            if "\n" in match.group(1):
                line = text[:match.start()].count("\n") + 1
                wrapped.append(f"{path.relative_to(REPO_ROOT)}:{line}")
    assert wrapped == [], f"wrap before the role, not inside it: {wrapped}"


def test_the_role_targets_the_unwrapping_exposed_all_resolve():
    """The unwrapping is only right if the joined target names something — the
    audit measured all of them resolvable after whitespace normalisation, and
    this is that measurement kept."""
    unresolved = []
    for relative in ("gcp_grounding/cli.py", "gcp_grounding/drift.py",
                     "gcp_grounding/gate.py", "gcp_grounding/iam_scope.py",
                     "gcp_grounding/provider_schema.py",
                     "gcp_grounding/reconciled.py", "gcp_grounding/registry.py",
                     "gcp_grounding/sec_domains.py", "gcp_grounding/sources.py"):
        for match in ROLE.finditer(source_of(relative)):
            target = match.group(1)
            if not target.startswith("gcp_grounding"):
                continue
            if not resolves(target):
                unresolved.append(f"{relative}: {target}")
    assert unresolved == [], unresolved


# -- R13: the terraform precondition, and what it costs when unmet -------------


def test_a_tf_json_proposal_with_a_snapshot_alone_checks_nothing(capsys):
    """The behaviour both pages now state. It is not a refusal and not a false
    pass — it is exit 0 with the headline saying nothing was verified, which is
    why a reader who watches only the exit code is misled."""
    proposal = REPO_ROOT / "examples" / "terraform-schema" / "proposal_ok.tf.json"
    code = main(["verify-policy", str(proposal), "--snapshot",
                 str(AGENTIC_SNAPSHOT), "--no-config"])
    out = capsys.readouterr().out
    assert code == 0
    assert "PASSED — NOTHING VERIFIED" in out
    assert f"? [document] {proposal}: document kind was not recognized" in out


def test_a_tf_json_proposal_is_judged_once_a_state_option_is_configured(capsys):
    """The other half of the same sentence: the reader is told to add one of
    these options, so adding one has to be what routes the document."""
    code = main(["verify-policy", "--proposal", str(MASKED / "base.tf.json"),
                 "--snapshot", str(AGENTIC_SNAPSHOT),
                 "--terraform-state", str(MASKED / "terraform.tfstate"),
                 "--no-config"])
    out = capsys.readouterr().out
    assert code == 1
    assert "document kind was not recognized" not in out


def section(text: str, heading: str) -> str:
    """*text* from *heading* up to the next same-level heading."""
    start = text.index(heading)
    rest = text.index("\n## ", start + len(heading))
    return text[start:rest]


@pytest.mark.parametrize("page,text", [
    # The README says it correctly in §"Proposing a terraform change", 500 lines
    # below where the reader meets `.tf` — so the pin is on the EARLIER section,
    # which is the half R13 asked for.
    ("README.md §The three inputs", section(README, "## The three inputs")),
    ("simple_readme.md", SIMPLE),
])
def test_both_pages_state_the_precondition_and_what_an_unmet_one_costs(page, text):
    """R13 was one finding at two doc sites: the rule was stated (or implied)
    on both pages and the consequence on neither, where the reader meets it."""
    body = flat(text)
    for option in ("`--terraform-state`", "`--terraform-plan`",
                   "`--terraform-dir`", "`--provider-schema`"):
        assert option in body, (page, option)
    assert "PASSED — NOTHING VERIFIED" in body, page
    assert ("nothing was checked" in body
            or "document kind was not recognized" in body), page


# -- R14: the iam_deny_shadow limit the stated-limits paragraph omitted --------


def test_the_readme_states_the_rest_allow_policy_limit_in_its_own_words():
    """The paragraph promises its limits are "stated rather than papered over",
    and this one was not among them: over a REST allow policy the estate-side
    masked and threaded arcs can only ever abstain, because the document names
    no project for ``_governs`` to place. Pinned against the real message."""
    document = {"bindings": [{"role": "roles/owner", "members": ["allUsers"]}]}
    grants = iam_deny_checks._document_grants(document)
    assert grants, "an allow policy with one readable binding yields one grant"
    assert all(not getattr(grant, "project", "") for grant in grants), \
        "a REST allow policy carries no project — the whole premise of this row"

    quoted = "the grant names no readable project, so whether the deny policy " \
             "attached at"
    assert quoted in flat(README), "the stated-limits paragraph dropped the clause"
    assert quoted in flat(iam_deny_checks._governs(
        "projects/acme-prod", "", None).reason)


# -- R16: the drill-down block quotes lines the renderer can print -------------


def test_the_state_explain_drill_down_block_carries_every_rendered_field():
    """The quoted ``chosen:`` line had five of the renderer's seven fields —
    ``origin=`` and ``captured_at=`` were absent — and each alternate's
    mandatory ``record:`` line was dropped. Both are checked against a real
    render, so the block cannot drift back."""
    key = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
    rendered = two_source_drill_down("iam_bindings", key)
    chosen = next(line for line in rendered if line.startswith("  chosen:"))
    labels = [label for label in
              ("source=", "[", "origin=", "locator=", "captured_at=",
               "domain-scope=", "taint=") if label in chosen]
    assert len(labels) == 7, chosen

    block = next(b for b in re.findall(r"```text\n(.*?)```", README, re.S)
                 if b.startswith(f"state fact iam_bindings {key}:"))
    quoted = flat(block[:block.index("\n  alternates:")])
    for label in labels:
        assert label in quoted, f"the quoted chosen: line drops {label}"

    # Every alternate the renderer prints is followed by its own record line.
    rendered_pairs = [(a, b) for a, b in zip(rendered, rendered[1:])
                      if a.lstrip().startswith("alternate:")]
    assert rendered_pairs and all(b.lstrip().startswith("record:")
                                  for _a, b in rendered_pairs)
    lines = [line.rstrip() for line in block.splitlines()]
    starts = [i for i, line in enumerate(lines)
              if line.lstrip().startswith("alternate:")]
    assert starts, "the quoted block no longer shows an alternate"
    for index in starts:
        tail = lines[index + 1:]
        assert any(line.lstrip().startswith("record:") for line in tail), \
            "the quoted alternate has no record: line"


# -- R34, R35, R36: the elisions the page makes are the page's own -------------


@_needs_z3
def test_the_9e_check_listing_is_quoted_without_its_provenance_suffix(
        masked_narrowed, monkeypatch, capsys):
    """R34. Each quoted ``✓`` line really ends with provenance the quote drops.
    Dropping it is defensible — it is identical on every line of a run — but it
    was nowhere stated, so a reader diffing against their terminal found three
    lines that did not match. The statement is now on the page; this pins that
    it is TRUE of the run the block quotes."""
    # Relative paths, from the repo root: the pair check names its target by the
    # path it was given, and the README quotes the runner's relative spelling.
    monkeypatch.chdir(REPO_ROOT)
    code = main(["verify-policy",
                 "--proposal", "examples/terraform-masked/narrowed.tf.json",
                 "--snapshot", str(AGENTIC_SNAPSHOT), "--terraform-state",
                 "examples/terraform-masked/terraform-after-removal.tfstate",
                 "--requirements", str(masked_narrowed), "--explain", "--no-config"])
    listing = check_lines(capsys.readouterr().out)
    assert code == 0

    pair = next(line for line in listing if "[firewall_pair]" in line)
    for suffix in ("[pair scope ", "[target ", " | source ", " | how ", "[snapshot "):
        assert suffix in pair, suffix
    exposure = next(line for line in listing if "[firewall_exposure]" in line)
    assert exposure.endswith("]"), "every line carries at least the snapshot suffix"

    # What the page quotes is each line with that tail cut off.
    body = flat(README)
    for quoted in ("✓ [firewall_exposure] google_compute_firewall.allow_rdp_broad: "
                   "no public source reaches a sensitive port",
                   "✓ [firewall_pair] examples/terraform-masked/narrowed.tf.json: "
                   "the new rule set allows no packet the old set denied"):
        assert quoted in body, quoted
        assert printed(listing, quoted), f"the run no longer prints {quoted!r}"

    assert "provenance suffix" in body, \
        "the page must state the convention it uses in twenty blocks"


@_needs_z3
def test_the_12a_check_listing_marks_the_lines_it_leaves_out(tmp_path, capsys):
    """R35. Three contiguous ``✓`` lines were presented as "the check listing";
    the real listing carries fifteen before them and two more among them, with
    no ``…`` anywhere. Each quoted line is byte-exact, so the defect is the
    unmarked gap and nothing else."""
    out = tmp_path / "compiled-denypolicy"
    assert main(["compile-requirements", str(DENYPOLICY), "--snapshot",
                 str(DENYPOLICY / "snapshot.json"), "--out", str(out)]) == 0
    capsys.readouterr()
    code = main(["verify-policy", "--proposal", str(DENYPOLICY / "plan_base.json"),
                 "--snapshot", str(DENYPOLICY / "snapshot.json"),
                 "--requirements", str(out), "--explain", "--no-config"])
    listing = check_lines(capsys.readouterr().out)
    assert code == 0

    block = next(b for b in re.findall(r"```text\n(.*?)```", README, re.S)
                 if "✓ [iam_deny_shadow] google_project_iam_binding."
                    "payroll_ci_token_creator:" in b)
    quoted = [flat(chunk) for chunk in re.split(r"\n(?=✓|…)", block)
              if chunk.strip() and not chunk.startswith("…")]
    for line in quoted:
        assert printed(listing, line), f"the run no longer prints {line!r}"
    assert len(listing) > len(quoted), \
        "this pin is only about a SELECTION; the block now quotes everything"
    assert block.startswith("…\n") and block.rstrip().endswith("…"), \
        "the dropped lines above and below the selection are unmarked"
    assert "\n…\n" in block.strip("…\n"), \
        "the two lines dropped INSIDE the selection are unmarked"


@_needs_z3
def test_the_firewall_reopen_witnesses_are_quoted_the_way_they_print(
        tmp_path, capsys):
    """R36. ``[firewall_exposure]`` prints its solver-minted address inside
    parentheses of its own, so the page's ``(…)`` mask is byte-faithful there.
    ``[firewall_reopen]`` prints them bare, and the page masked them the same
    way — a difference its stated convention does not explain."""
    out = tmp_path / "compiled-orgpolicy"
    assert main(["compile-requirements", str(ORGPOLICY), "--snapshot",
                 str(ORGPOLICY / "snapshot.json"), "--out", str(out)]) == 0
    capsys.readouterr()
    code = main(["verify-policy",
                 "--proposal", str(ORGPOLICY / "proposal_egress_world.tf.json"),
                 "--snapshot", str(ORGPOLICY / "snapshot.json"),
                 "--terraform-state", str(ORGPOLICY / "terraform.tfstate"),
                 "--requirements", str(out), "--explain", "--no-config"])
    text = capsys.readouterr().out
    assert code == 1

    reopen = next(flat(line) for line in text.splitlines()
                  if "⚠ [firewall_reopen]" in line and "e.g. src" in line)
    assert re.search(r"e\.g\. src [\d.]+; dst [\d.]+; protocol \d+; port \d+",
                     reopen), reopen
    assert "src (" not in reopen and "dst (" not in reopen

    body = flat(README)
    assert "e.g. src …; dst …; protocol 6; port 443" in body
    assert "e.g. src (…); dst (…)" not in body


# -- R37: the walkthrough promise block, quoted whole -------------------------


def test_the_readme_quotes_the_committed_promise_block_whole():
    """The quote dropped the corpus's two ``note:`` lines from INSIDE the fence,
    which is the one elision a reader cannot see. Quoting the block whole makes
    the page byte-comparable with the file, which is what this pins."""
    corpus = (WALKTHROUGH / "requirements.md").read_text(encoding="utf-8")
    opened = corpus.index("```promise")
    block = corpus[opened:corpus.index("\n```", opened + 3) + 4].rstrip("\n")
    assert block.count("note: ") == 2, "the corpus no longer carries two notes"
    assert block in README, \
        "the README quote of examples/walkthrough/requirements.md is not the file"


# -- R17, R18, R52, R54: the authoring guide ----------------------------------


def test_the_authoring_guide_holds_the_full_collection_table():
    """R18 — ``README.md`` calls this file "the canonical grammar: … and the
    full collection table", and it tabulated four of fifteen collections. R17 —
    the prose that named the rest said "six more once it lands", of eleven that
    had landed. One table in both files closes both rows; this keeps the two
    copies equal, and equal to the registry."""
    sec_domains.register()
    rows = collection_table(AUTHORING)
    assert rows == collection_table(README), \
        "the two copies of the collection table have drifted apart"

    named = set()
    for row in rows:
        named.update(re.findall(r"`([a-z_]+)`", row.split("|")[2]))
    assert named == registry_names(), \
        f"table vs registry: {sorted(named ^ registry_names())}"
    assert "once it lands" not in AUTHORING


@pytest.mark.parametrize("task_id,module", [("sx-sec-parse", sec_parse),
                                            ("sx-sec-domains", sec_domains)])
def test_the_authoring_guide_names_modules_and_not_design_task_ids(task_id, module):
    """R54. A user-facing guide named two design task ids, which correspond to
    no file, module or entry point a reader can open."""
    relative = f"gcp_grounding/{module.__name__.rsplit('.', 1)[-1]}.py"
    assert (REPO_ROOT / relative).is_file()
    assert f"`{relative}`" in AUTHORING, relative
    assert task_id not in AUTHORING, task_id


def test_the_authoring_guide_says_the_shipped_directory_holds_no_documents():
    """R52. Both pages tell a reader to commit artifacts to
    ``sec_requirements/compiled/``; the shipped directory holds the template and
    this README, discovery skips both, and the first run a reader makes compiles
    zero documents. The guide now says so and names the corpora that do exist."""
    shipped = REPO_ROOT / "sec_requirements"
    assert sorted(p.name for p in shipped.iterdir()) == ["README.md", "TEMPLATE.md"]
    assert sec_parse.discover(str(shipped)) == ()
    assert not (shipped / "compiled").exists()

    body = flat(AUTHORING)
    assert "compiles **zero** documents" in body
    for corpus in ("tests/fixtures/gcp/sec_requirements/",
                   "examples/walkthrough/requirements.md"):
        assert f"`{corpus}`" in body, corpus
        found = sec_parse.discover(str(REPO_ROOT / corpus.rstrip("/")))
        assert found or (REPO_ROOT / corpus).is_file(), corpus


# -- R55: the walkthrough arc's order ----------------------------------------


def test_the_readme_lists_the_w_arc_steps_in_the_order_the_runner_runs_them():
    """R55. The page said "the compile of step three above, then the verify
    below and its REST-policy counterpart"; the runner's order is the other way
    round, and the page's own later sentence ("is step two of the arc") knew
    it."""
    arc = RUN_DEMO[RUN_DEMO.index("\n    w)"):]
    arc = arc[:arc.index(";;")]
    rest, terraform = arc.index("policy.json"), arc.index("proposal.tf.json")
    assert rest < terraform, "the runner's own order changed; re-read the page"
    assert "the REST-policy counterpart and the verify below, in that order" \
        in flat(README)


