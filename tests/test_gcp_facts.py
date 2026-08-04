"""The shared fact vocabulary: the ignorance marker, the deep walkers, the
proposal sanitizer, the two frozen types and the category partition.

Every assertion here is about a rule that, if it broke, would turn a
"terraform did not tell us" into a confident answer: a marker that truth-tests
as empty, a detail that reaches a log line, an attribute silently stripped out
of a proposal, a proposed change constructed as current state, or a category
terraform does not enumerate being treated as authoritative.
"""

import ast
import dataclasses
import importlib
import importlib.util
from pathlib import Path

import pytest

from gcp_grounding import facts
from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot

# provenance.py is a sibling module of this design and may not have landed on
# this branch yet. Branch on the capability with a plain module-level boolean
# (the suite's HAVE_Z3 idiom) rather than skipping, so its absence is asserted
# to degrade honestly instead of quietly deleting a test.
HAVE_PROVENANCE = importlib.util.find_spec("gcp_grounding.provenance") is not None

# Current-state source spellings this design uses. Strings, not imports: the
# point of the assertions below is that none of them may take the proposed side.
CURRENT_SPELLINGS = ("tfstate", "tfplan-prior", "hcl-current", "api", "baseline")


def firewall_doc():
    """A firewall-shaped document with markers at three different path forms."""
    return {
        "name": "allow-ssh",
        "network": facts.Unresolved("interpolation", "values.network"),
        "allow": [{"protocol": "tcp",
                   "ports": facts.Unresolved("for_each", "values.allow[0].ports")}],
        "rule": [
            {"match": {"expr": "true"}},
            {"match": {"expr": facts.Unresolved("function_call",
                                                "values.rule[1].match.expr")}},
        ],
    }


# -- the ignorance marker -----------------------------------------------------


def test_truth_testing_a_marker_raises_like_unknown():
    marker = facts.Unresolved("interpolation", "values.network")

    with pytest.raises(TypeError) as marker_exc:
        bool(marker)
    with pytest.raises(TypeError) as unknown_exc:
        bool(UNKNOWN)

    marker_msg, unknown_msg = str(marker_exc.value), str(unknown_exc.value)
    # Same SHAPE of message as knowledge.Unknown's: says it is neither, says
    # what to compare with instead, and names the honest verdict.
    for fragment in ("neither True nor False", "compare with",
                     "'unverified'", "never 'ungrounded'"):
        assert fragment in marker_msg, fragment
        assert fragment in unknown_msg, fragment


def test_the_naive_emptiness_check_cannot_swallow_a_marker():
    def naive(values):
        if not values["network"]:      # the exact mistake the marker forbids
            return "empty"
        return "set"

    assert naive({"network": []}) == "empty"
    with pytest.raises(TypeError):
        naive({"network": facts.Unresolved("interpolation", "values.network")})


def test_repr_never_carries_the_detail():
    marker = facts.Unresolved("heredoc", "values.metadata.startup_script",
                              detail="ghp_0123456789abcdefghij")
    text = repr(marker)
    assert "ghp_0123456789abcdefghij" not in text
    assert "detail" not in text
    assert text == ("Unresolved(reason='heredoc', "
                    "path='values.metadata.startup_script')")
    # …and the same holds for the repr of a container holding one, which is
    # what a pytest assertion dump or a log line actually renders.
    assert "ghp_" not in repr({"script": marker})
    assert marker.detail == "ghp_0123456789abcdefghij"   # still available to code


def test_a_sensitive_reason_may_not_carry_a_detail():
    assert facts.Unresolved("sensitive", "values.password").detail == ""
    with pytest.raises(ValueError, match="sensitive"):
        facts.Unresolved("sensitive", "values.password", detail="hunter2")


def test_marker_construction_refuses_nonsense():
    with pytest.raises(ValueError, match="not one of"):
        facts.Unresolved("because_reasons", "values.network")
    with pytest.raises(ValueError, match="path"):
        facts.Unresolved("interpolation", "")
    with pytest.raises(ValueError, match="MAX_DETAIL"):
        facts.Unresolved("unparsed", "values.x", detail="x" * (facts.MAX_DETAIL + 1))
    for reason in ("interpolation", "count", "for_each", "dynamic_block",
                   "function_call", "heredoc", "provider_alias", "missing_project",
                   "unknown_after_apply", "sensitive", "unparsed", "ambiguous_key"):
        assert reason in facts.UNRESOLVED_REASONS


def test_marker_is_frozen():
    marker = facts.Unresolved("count", "values.name")
    with pytest.raises(dataclasses.FrozenInstanceError):
        marker.reason = "for_each"


def test_truncate_produces_a_legal_detail():
    clipped = facts.truncate("x" * 500)
    assert len(clipped) == facts.MAX_DETAIL
    assert clipped.endswith("…")
    assert facts.truncate("short") == "short"
    facts.Unresolved("unparsed", "values.x", detail=clipped)   # constructs


# -- the deep walkers ---------------------------------------------------------


def test_walker_yields_dotted_and_indexed_paths():
    doc = firewall_doc()

    pairs = list(facts.unresolved_in(doc))

    assert [path for path, _ in pairs] == ["allow[0].ports", "network",
                                           "rule[1].match.expr"]
    assert [marker.reason for _, marker in pairs] == ["for_each", "interpolation",
                                                      "function_call"]
    assert facts.first_unresolved(doc)[0] == "allow[0].ports"
    assert facts.has_unresolved(doc) is True
    assert facts.has_unresolved({"name": "allow-ssh", "allow": [{"ports": ["22"]}]}) is False
    assert facts.first_unresolved({"a": 1}) is None
    assert facts.is_unresolved(doc["network"]) is True
    assert facts.is_unresolved(doc["name"]) is False


def test_deep_nesting_degrades_to_one_marker_instead_of_recursing():
    deep = {"leaf": facts.Unresolved("unparsed", "values.leaf")}
    for _ in range(200):
        deep = {"nested": deep}

    pairs = list(facts.unresolved_in(deep))         # must not raise

    assert len(pairs) == 1
    path, marker = pairs[0]
    assert marker.reason == "depth_cap"
    assert path.count(".") == facts.MAX_DEPTH - 1   # capped exactly at the cap
    assert facts.has_unresolved(deep) is True


# -- interpolation ------------------------------------------------------------


def test_is_interpolated_is_a_substring_test():
    # Partial interpolation: a startswith test would call this a literal role
    # name and ground it against a role nobody ever wrote.
    assert facts.is_interpolated("roles/${var.tier}.admin") is True
    assert facts.is_interpolated("${var.network}") is True
    # The escaped literal is refused too — deliberately conservative.
    assert facts.is_interpolated("$${not_really_a_var}") is True
    assert facts.is_interpolated("roles/bigquery.dataViewer") is False
    assert facts.is_interpolated("") is False


# -- the proposal sanitizer ---------------------------------------------------


def test_strip_unresolved_removes_rather_than_nulls():
    doc = firewall_doc()

    sanitized, removed = facts.strip_unresolved(doc)

    assert removed == ("allow[0].ports", "network", "rule[1].match.expr")
    assert list(removed) == sorted(removed)
    # REMOVED, not nulled: an explicit null would read as a value to every
    # extractor in this repo, which skips absent keys conservatively.
    assert "network" not in sanitized
    assert sanitized["allow"] == [{"protocol": "tcp"}]
    assert sanitized["rule"][1]["match"] == {}
    assert sanitized["rule"][0]["match"]["expr"] == "true"
    assert sanitized["name"] == "allow-ssh"
    assert not facts.has_unresolved(sanitized)


def test_strip_unresolved_does_not_mutate_the_original():
    doc = firewall_doc()

    sanitized, removed = facts.strip_unresolved(doc)

    assert doc == firewall_doc()
    assert facts.is_unresolved(doc["network"])
    assert facts.is_unresolved(doc["allow"][0]["ports"])
    assert sanitized["allow"] is not doc["allow"]
    assert removed


def test_strip_unresolved_leaves_a_clean_document_alone():
    doc = {"name": "allow-ssh", "allow": [{"protocol": "tcp", "ports": ["22"]}]}

    sanitized, removed = facts.strip_unresolved(doc)

    assert sanitized == doc
    assert removed == ()


# -- logging ------------------------------------------------------------------


def test_safe_repr_never_renders_string_content():
    secret = "sk-live-" + "a" * 4992

    rendered = facts.safe_repr(secret)

    assert rendered == "<str len=5000>"
    assert len(rendered) < 40
    assert "sk-live" not in rendered
    assert "a" * 8 not in rendered
    assert facts.safe_repr({"a": 1, "b": 2}) == "<mapping keys=2>"
    assert facts.safe_repr(["22", "443"]) == "<list len=2>"
    assert facts.safe_repr(None) == "None"
    assert "detail" not in facts.safe_repr(
        facts.Unresolved("heredoc", "values.script", detail="ghp_secretish"))


# -- the proposed-source vocabulary -------------------------------------------


def test_proposed_sources_are_disjoint_from_current_state_spellings():
    assert facts.PROPOSED_SOURCES == ("tfplan-planned", "hcl-proposed")

    if HAVE_PROVENANCE:
        provenance = importlib.import_module("gcp_grounding.provenance")
        assert set(facts.PROPOSED_SOURCES).isdisjoint(set(provenance.SOURCES))
        for spelling in facts.PROPOSED_SOURCES:
            # A proposed fact never participates in a winner selection, so
            # ranking one is never a meaningful question.
            with pytest.raises((ValueError, KeyError, TypeError)):
                provenance.fidelity_rank(spelling)
    else:
        # provenance.py has not landed here. The cross-module half of the pin
        # cannot run; assert the half that IS decidable in this module — no
        # current-state spelling can take the proposed side, and no proposed
        # spelling can take the current one — rather than skipping.
        for spelling in CURRENT_SPELLINGS:
            assert spelling not in facts.PROPOSED_SOURCES
            with pytest.raises(ValueError):
                facts.TfObject(address="google_compute_firewall.a",
                               type="google_compute_firewall", name="a",
                               source=spelling, side="proposed")


def test_facts_imports_only_stdlib_and_core_log():
    """The layering rule, pinned: facts.py is the flat vocabulary, so it may
    not import knowledge, provenance or anything under tfsource."""
    tree = ast.parse(Path(facts.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add("." * node.level + (node.module or ""))

    assert imported <= {"__future__", "copy", "dataclasses", "typing", ".core.log"}
    assert not any("tfsource" in name or "knowledge" in name or "provenance" in name
                   for name in imported)


# -- the types ----------------------------------------------------------------


def _tf_object(**overrides):
    kwargs = dict(address="google_compute_firewall.allow_ssh",
                  type="google_compute_firewall", name="allow_ssh",
                  source="tfstate", side="current")
    kwargs.update(overrides)
    return facts.TfObject(**kwargs)


def test_tfobject_refuses_a_proposed_source_on_the_current_side():
    with pytest.raises(ValueError) as exc:
        _tf_object(source="tfplan-planned", side="current")
    assert "tfplan-planned" in str(exc.value)


def test_tfobject_refuses_a_current_source_on_the_proposed_side():
    with pytest.raises(ValueError) as exc:
        _tf_object(source="tfstate", side="proposed")
    assert "tfstate" in str(exc.value)


def test_tfobject_accepts_each_side_with_its_own_spelling():
    current = _tf_object(values={"network": "projects/p/global/networks/vpc"})
    planned = _tf_object(source="tfplan-planned", side="proposed",
                         notes=["from resource_changes"])

    assert current.side == "current" and current.source == "tfstate"
    assert planned.side == "proposed"
    assert planned.notes == ("from resource_changes",)      # normalized to a tuple
    for spelling in facts.PROPOSED_SOURCES:
        assert _tf_object(source=spelling, side="proposed").source == spelling


def test_tfobject_is_frozen_and_needs_an_address():
    with pytest.raises(ValueError, match="address"):
        _tf_object(address="")
    with pytest.raises(dataclasses.FrozenInstanceError):
        _tf_object().address = "other"


# -- the category partition ---------------------------------------------------


def test_the_partition_is_a_partition():
    flat, table = set(facts.FLAT_CATEGORIES), set(facts.TABLE_CATEGORIES)

    assert flat | table == set(facts.TF_CATEGORIES)
    assert flat & table == set()
    assert len(facts.TF_CATEGORIES) == len(set(facts.TF_CATEGORIES)) == 14
    assert "roles" in table          # a custom role carries its permissions


def test_every_category_is_a_real_estate_category():
    snapshot_categories = {f.name for f in dataclasses.fields(GcpSnapshot)
                           if f.name != "captured_at"}

    assert set(facts.TF_CATEGORIES) <= snapshot_categories
    # …and the excluded four account for exactly the rest of the estate.
    assert set(facts.TF_CATEGORIES) | set(facts.EXCLUDED_CATEGORIES) == snapshot_categories


def test_the_excluded_categories_are_excluded_with_a_reason():
    for name in ("permissions", "principals", "constraints", "resource_types"):
        assert name not in facts.TF_CATEGORIES
        assert facts.EXCLUDED_CATEGORIES[name].strip()
        with pytest.raises(ValueError) as exc:
            facts.Fact(category=name, key="whatever", source="tfstate", side="current")
        assert "TF_CATEGORIES" in str(exc.value)


def test_fact_record_is_none_exactly_for_a_flat_category():
    flat = facts.Fact(category="networks", key="projects/p/global/networks/vpc",
                      source="tfstate", side="current")
    table = facts.Fact(category="firewall_rules",
                       key="projects/p/global/firewalls/allow-ssh",
                       record={"network": "projects/p/global/networks/vpc"},
                       source="tfstate", side="current", fragment="allow")

    assert flat.record is None
    assert table.record["network"] == "projects/p/global/networks/vpc"

    with pytest.raises(ValueError, match="flat category"):
        facts.Fact(category="networks", key="projects/p/global/networks/vpc",
                   record={"anything": 1}, source="tfstate", side="current")
    with pytest.raises(ValueError, match="table category"):
        facts.Fact(category="firewall_rules", key="projects/p/global/firewalls/a",
                   source="tfstate", side="current")


def test_fragment_is_only_meaningful_for_a_table_category():
    with pytest.raises(ValueError, match="fragment"):
        facts.Fact(category="network_tags", key="web", fragment="rules",
                   source="tfstate", side="current")


def test_fact_carries_the_same_side_invariant():
    with pytest.raises(ValueError):
        facts.Fact(category="networks", key="projects/p/global/networks/vpc",
                   source="hcl-proposed", side="current")
    assert facts.Fact(category="networks", key="projects/p/global/networks/vpc",
                      source="hcl-proposed", side="proposed").side == "proposed"


# -- the tfsource package -----------------------------------------------------


def test_tfsource_package_is_docstring_only():
    package = importlib.import_module("gcp_grounding.tfsource")
    body = ast.parse(Path(package.__file__).read_text(encoding="utf-8")).body

    assert len(body) == 1 and isinstance(body[0], ast.Expr)     # nothing but a docstring
    doc = package.__doc__
    for phrase in ("discover", "read", "map", "resolve", "assemble",
                   "imports", "submodules"):
        assert phrase in doc, phrase
