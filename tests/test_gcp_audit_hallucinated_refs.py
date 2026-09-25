"""The regression net for the six hallucinated references, audit rows R07-R12.

Each of the six named a thing that does not exist, in text the project hands to
someone who will then go looking for it:

* R07/H1 — ``baseline.REMEDIES[0]`` told an operator to pass ``--baseline-target``.
  The verdict that carries it is remediation text printed at an agent, so a flag
  argparse never defined costs a retry loop. Pinned here against the PARSER,
  not against a spelling, so the remedy cannot name a flag again without the
  flag existing.
* R08/H2 — two ``sources.py`` docstrings offered a config-file key for
  ``completeness``. Writing the key does not demote one setting, it makes
  :func:`gcp_grounding.discovery.discover` refuse the WHOLE config file, so the
  sentence sent a reader to a state strictly worse than the one they were in.
* R09/H3 and R10/H4 — ``identity.CATEGORY_SPECS`` and
  ``gcp_grounding.tfsource.merge``, six cross-references between them, none
  resolvable. Pinned by RESOLVING every ``gcp_grounding`` cross-reference in
  the two modules those rows name.
* R11/H5 — a strict xfail whose reason was headed
  ``ORG-EFFECTIVE-REGISTER-ACTIVATION``, an id in no register, so the frozen
  self-test (which walks register -> node) could not see the node at all.
  Pinned over EVERY strict xfail that uses the id-naming position.
* R12/H6 — the escalation register's own docstring described closure through a
  ``closed_by`` field :class:`~tests.escalations.Escalation` does not have.

SCOPE OF THE CROSS-REFERENCE CHECK, STATED SO NOBODY READS IT AS A CLEAN BILL
FOR THE PACKAGE: it resolves the two modules R09 and R10 name, which is the
scope those rows own. A package-wide sweep is a different and larger change
than the one the rows proposed.

The resolver is ANNOTATION-AWARE on purpose: a frozen dataclass field with no
default is a real member that ``hasattr`` cannot see, and treating those four
(``merge.MergeResult.declared_not_applied`` and friends) as hallucinations
would make this file lie in the other direction.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib
import re
from pathlib import Path

import pytest

from gcp_grounding import baseline, cli, discovery, sources
from tests import escalations
from tests.escalations import ESCALATIONS, PRODUCT_ESCALATIONS

REPO_ROOT = Path(__file__).resolve().parents[1]

#: The two modules rows R09 and R10 name. Their cross-references are resolved
#: in full, because that is the scope the rows own.
CROSS_REFERENCE_MODULES = (
    "gcp_grounding/knowledge.py",
    "gcp_grounding/tfsource/map_network.py",
)

#: A Sphinx cross-reference into this package. ``~`` is Sphinx's "print the
#: last component only" prefix and says nothing about the target.
REFERENCE = re.compile(
    r":(?:mod|data|class|func|attr|meth|exc|const):`~?(gcp_grounding[\w.]*)`")

#: Every ``--flag`` spelling a string can carry.
FLAG = re.compile(r"--[a-z0-9][a-z0-9-]*")


# -- helpers ------------------------------------------------------------------


def option_strings(parser: argparse.ArgumentParser) -> set[str]:
    """Every option this parser or any subparser of it defines."""
    found: set[str] = set()
    for action in parser._actions:
        found.update(action.option_strings)
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                found |= option_strings(sub)
    return found


def metavar_of(parser: argparse.ArgumentParser, option: str) -> str | None:
    """The metavar argparse advertises for ``option``, searched depth-first."""
    for action in parser._actions:
        if option in action.option_strings:
            return action.metavar
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                found = metavar_of(sub, option)
                if found is not None:
                    return found
    return None


def unresolved(dotted: str) -> str | None:
    """None when the dotted name names something, else why it does not.

    Imports the longest importable prefix and then walks attributes, counting a
    dataclass field declared with no default — which lives in
    ``__annotations__`` and nowhere else — as present.
    """
    parts = dotted.split(".")
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
        return f"{dotted}: no importable module in it"
    for name in parts[depth:]:
        annotations = getattr(obj, "__annotations__", {})
        if hasattr(obj, name):
            obj = getattr(obj, name)
        elif name in annotations:
            return None  # a field's own members are not resolvable from here
        else:
            return f"{dotted}: {name} is not there"
    return None


def strict_xfail_reasons() -> list[tuple[str, int, str]]:
    """(module, line, reason) for every ``xfail(strict=True)`` under ``tests/``.

    Read with :mod:`ast` rather than by importing, the same reason
    ``tests/test_gcp_escalations.py`` gives: a node must stay legible in a
    checkout where its module does not import.
    """
    import ast

    found: list[tuple[str, int, str]] = []
    for path in sorted((REPO_ROOT / "tests").glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not ast.unparse(node.func).endswith("xfail"):
                continue
            keywords = {k.arg: k.value for k in node.keywords if k.arg}
            strict = keywords.get("strict")
            if not (isinstance(strict, ast.Constant) and strict.value is True):
                continue
            reason = keywords.get("reason")
            if reason is None:
                continue
            try:
                text = ast.literal_eval(reason)
            except (ValueError, SyntaxError):
                continue
            found.append((path.name, node.lineno, str(text)))
    return found


def sentences(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?<=\.)\s+", " ".join(text.split()))]


# -- R07/H1: the remedy names a flag the parser defines -----------------------


def test_no_baseline_remedy_names_a_flag_the_parser_does_not_define():
    """R07: ``REMEDIES[0]`` named ``--baseline-target``, which argparse has never
    defined — so the one remedy an agent can act on alone was unusable.

    Pinned against ``cli.build_parser()`` rather than against the new spelling:
    a remedy may name any flag, as long as the flag is real.
    """
    defined = option_strings(cli.build_parser())
    named = sorted(set(FLAG.findall(" ".join(baseline.REMEDIES))))
    assert named, "the remedies name no flag at all, so this pin proves nothing"
    missing = [flag for flag in named if flag not in defined]
    assert not missing, (
        f"baseline.REMEDIES names flags argparse does not define: {missing}. "
        "This text is printed at an operator or an agent inside the "
        f"{baseline.TARGET_KIND!r} verdict, so a flag that does not exist is a "
        "retry loop with a confident instruction at the top of it."
    )


def test_the_explicit_remedy_names_the_target_flag_with_its_own_metavar():
    """R07: and it names ``--target`` the way ``--help`` does, DOMAIN:KEY and
    all, because half a flag is a second thing to go and look up."""
    parser = cli.build_parser()
    metavar = metavar_of(parser, "--target")
    assert metavar == "DOMAIN:KEY", metavar
    assert f"--target {metavar}" in baseline.REMEDIES[0], baseline.REMEDIES[0]
    assert "--baseline-target" not in " ".join(baseline.REMEDIES)


# -- R08/H2: no docstring offers a config key for completeness ----------------


def test_completeness_really_has_no_config_file_key():
    """The fact the docstrings contradicted. Recorded first, so the pin below
    is grounded in the parser rather than in a preference."""
    assert "completeness" not in discovery.CONFIG_KEYS
    assert "completeness" not in discovery.TERRAFORM_KEYS


@pytest.mark.parametrize("doc", [
    pytest.param(sources.__doc__, id="module"),
    pytest.param(sources.LoadedSource.declared_scope.__doc__, id="declared_scope"),
])
def test_no_completeness_docstring_offers_a_config_key(doc):
    """R08: both sites said ``--completeness`` "or the config key". Writing that
    key does not demote one setting — ``discovery.discover`` returns no config
    at all and names the key as unrecognized, so the whole file is refused."""
    assert doc is not None
    normalized = " ".join(doc.split())
    assert "config key" not in normalized, (
        "a docstring still offers a config-file key for --completeness; there "
        f"is none, and naming one costs the operator their whole config file: "
        f"{normalized[:400]}"
    )


# -- R09/H3 and R10/H4: the cross-references resolve --------------------------


@pytest.mark.parametrize("relative_path", CROSS_REFERENCE_MODULES)
def test_every_cross_reference_in_the_module_resolves(relative_path):
    """R09 and R10: ``identity.CATEGORY_SPECS`` and a ``tfsource.merge`` module
    that has never existed — the second one six times over five docstrings.

    A cross-reference is a reading instruction. One that names nothing sends the
    reader to a file that is not there, and it is the fastest way for a docstring
    to describe a design the code does not have.
    """
    text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
    problems = []
    for match in REFERENCE.finditer(text):
        problem = unresolved(match.group(1))
        if problem:
            line = text.count("\n", 0, match.start()) + 1
            problems.append(f"{relative_path}:{line} {match.group(0)} - {problem}")
    assert not problems, "\n".join(problems)


def test_the_resolver_can_still_tell_a_real_name_from_an_invented_one():
    """Must-fail-first for the sweep above: a resolver that accepted everything
    would make it vacuous, and both retired spellings must stay refused."""
    assert unresolved("gcp_grounding.identity.SPECS") is None
    assert unresolved("gcp_grounding.merge") is None
    assert unresolved("gcp_grounding.identity.CATEGORY_SPECS") is not None
    assert unresolved("gcp_grounding.tfsource.merge") is not None
    # the annotation arm: a frozen dataclass field with no default is real
    assert unresolved("gcp_grounding.merge.MergeResult.declared_not_applied") is None


# -- R11/H5: an id in the id-naming position names a registered escalation -----


def test_every_strict_xfail_that_names_an_id_names_a_registered_one():
    """R11: the org-effective activation node was headed
    ``ORG-EFFECTIVE-REGISTER-ACTIVATION``, in exactly the position the other
    strict xfails use to name their escalation — and that id was in no register,
    so ``tests/test_gcp_escalations.py``, which walks register -> node, could not
    see the node and nothing recorded the clause, the reason or the owner.

    A reason with no id head is a different and legal shape (a conditional xfail
    carrying prose), so only the id-naming position is checked.
    """
    head = re.compile(r"^([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+):")
    registered = ({item.id for item in ESCALATIONS}
                  | {item.id for item in PRODUCT_ESCALATIONS})
    stray = []
    for module, line, reason in strict_xfail_reasons():
        match = head.match(reason.strip())
        if match and match.group(1) not in registered:
            stray.append(f"{module}:{line} names {match.group(1)}")
    assert not stray, (
        "strict xfails head their reason with an id that is in no register: "
        f"{stray}. The frozen self-test walks register -> node, so an id that "
        "is in nothing makes the node invisible to it: no clause, no owner, and "
        "no XPASS forcing a deliberate retirement."
    )


def test_the_org_effective_activation_escalation_is_the_registered_one():
    """R11, by name: the entry the row asked for, pointing at the node it
    parks, owned by the task the MK-F entries themselves record."""
    from tests import mutation_entries

    entry = next(item for item in ESCALATIONS
                 if item.id == "ESC-ORGEFF-REGISTER-ACTIVATION")
    assert entry.node_id == (
        "tests/test_gcp_org_effective.py::"
        "test_the_org_effective_mutation_entries_are_active_in_the_register")
    owners = {mutation.owner for mutation in mutation_entries.ORG_EFFECTIVE_ENTRIES}
    assert owners == {entry.owner_task}, owners
    assert entry.owner_task in escalations.OUT_OF_DOCUMENT_OWNER_TASKS


# -- R12/H6: the docstring describes the closure mechanism that exists ---------


def test_the_register_docstring_closes_an_entry_the_way_the_file_does():
    """R12: the docstring said a closed escalation's "entry stays, with
    ``closed_by`` naming the change". ``Escalation`` has no such field, and both
    retired entries had to be DELETED and replaced with a ``# RETIRED —``
    comment, which is what the file really does.
    """
    fields = {field.name for field in dataclasses.fields(escalations.Escalation)}
    product_only = {field.name for field
                    in dataclasses.fields(escalations.ProductEscalation)} - fields
    assert "closed_by" in product_only, (
        "this pin is built on closed_by belonging to ProductEscalation alone")

    doc = escalations.__doc__
    assert doc is not None
    closure = [line for line in sentences(doc) if "CLOSED" in line]
    assert closure, "the docstring no longer says how an escalation is closed"
    for sentence in closure:
        named = set(re.findall(r"``(\w+)``", sentence))
        invented = sorted(named & product_only)
        assert not invented, (
            f"the closure sentence attributes {invented} to an Escalation, "
            f"which has only {sorted(fields)}: {sentence}")
    assert any("RETIRED" in sentence for sentence in closure), (
        "the sentence must name the mechanism that shipped - the entry is "
        "deleted and a `# RETIRED -` comment records the closure")


def test_the_retirement_comments_the_docstring_describes_are_really_there():
    """Grounding for the sentence above: the practice it now documents is the
    one in the file, not a second description of something else."""
    source = (REPO_ROOT / "tests" / "escalations.py").read_text(encoding="utf-8")
    retired = [line.strip() for line in source.splitlines()
               if line.lstrip().startswith("# RETIRED —")]
    assert len(retired) >= 2, retired
    for line in retired:
        assert "ESC-" in line, line
    named = " ".join(retired)
    assert "ESC-GX-IAM-REPIN-SPLIT" in named and "ESC-GX-ABSTAIN-PASSED-HEADER" in named
    assert not any(entry.id in named for entry in ESCALATIONS), (
        "a retired id is still a live register entry, which is the state the "
        "docstring says cannot exist")
