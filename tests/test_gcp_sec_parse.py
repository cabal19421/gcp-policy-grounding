"""Tests for the Markdown front end (:mod:`gcp_grounding.sec_parse`).

Two halves. The first runs the parser over the committed offline corpus in
``tests/fixtures/gcp/sec`` and pins its documented outputs — the id sets, the
inherited/overridden headers, the six degenerate candidates, the literal source
line numbers, and that every parsed AST is its own :func:`sec_ast.canonical`.
The second writes tiny inline documents to ``tmp_path`` and pins each failure
mode: a tab, an odd indent, an unknown header key, a missing id, a duplicate id,
an unterminated fence, an unknown smt keyword, a wrong arity, an unrecognized
frontmatter key, and an unrecognized byte in the term language.
"""

from pathlib import Path

import pytest

from gcp_grounding import sec_ast
from gcp_grounding import sec_parse as m
from gcp_grounding.sec_parse import ParseError

SEC = Path(__file__).parent / "fixtures" / "gcp" / "sec"


def _by_id(doc):
    return {c.id: c for c in doc.candidates}


# -- discovery ----------------------------------------------------------------

def test_discover_returns_the_three_fixture_docs_sorted():
    got = m.discover(SEC)
    assert [p.name for p in got] == ["degenerate.md", "iam.md", "orgpolicy.md"]
    assert all(isinstance(p, Path) for p in got)


def test_discover_skips_readme_template_dot_and_underscore(tmp_path):
    for name in ("README.md", "TEMPLATE.md", "_draft.md", ".hidden.md", "keep.md"):
        (tmp_path / name).write_text("# x\n", encoding="utf-8")
    assert [p.name for p in m.discover(tmp_path)] == ["keep.md"]


def test_discover_missing_directory_is_empty_not_an_error():
    assert m.discover(SEC / "does-not-exist") == ()


# -- the committed corpus -----------------------------------------------------

def test_iam_three_ids_modes_and_inherited_state():
    doc = m.parse_file(SEC / "iam.md")
    by_id = _by_id(doc)
    assert set(by_id) == {
        "no-public-principals", "no-primitive-owner", "bindings-are-conditioned"}
    assert by_id["no-public-principals"].headers["mode"] == "refute"
    assert by_id["no-primitive-owner"].headers["mode"] == "refute"
    assert by_id["bindings-are-conditioned"].headers["mode"] == "assert_satisfiable"
    for cand in doc.candidates:
        # state is not set on any block, so every promise inherits the default.
        assert cand.headers["state"] == "proposal"
        assert cand.headers["domain"] == "iam"
        assert cand.error == ""
        assert cand.ast is not None
    # source.line points at the real prose sentence line in the file.
    assert by_id["no-public-principals"].line == 13
    assert by_id["no-primitive-owner"].line == 25
    assert by_id["bindings-are-conditioned"].line == 39
    assert by_id["no-public-principals"].text == \
        "IAM bindings must not grant access to the entire internet."
    assert doc.problems == ()


def test_orgpolicy_block_headers_override_state_and_domain():
    doc = m.parse_file(SEC / "orgpolicy.md")
    by_id = _by_id(doc)
    assert set(by_id) == {"serial-port-stays-disabled", "no-new-owner-grants"}

    override = by_id["no-new-owner-grants"]
    assert override.headers["state"] == "pair"    # block overrides frontmatter proposal
    assert override.headers["domain"] == "iam"     # block overrides frontmatter org_policy
    assert override.error == ""
    assert override.ast is not None
    assert override.line == 27

    default = by_id["serial-port-stays-disabled"]
    assert default.headers["state"] == "proposal"  # inherited
    assert default.headers["domain"] == "org_policy"
    assert default.line == 12


def test_degenerate_six_candidates_with_each_abstain_path():
    doc = m.parse_file(SEC / "degenerate.md")
    by_id = _by_id(doc)
    assert len(doc.candidates) == 6

    # A prose-only section: no fence, None ast, the untranslated marker, and an
    # id slugified from the heading under the untranslated- prefix.
    untranslated = by_id["untranslated-untranslated-requirement"]
    assert untranslated.ast is None
    assert untranslated.error == "no promise block — the sentence was not translated"
    assert untranslated.line == 83

    # An unregistered collection abstains, NAMING it. The case used
    # `firewall_rules`, which was unregistered while `sec_domains` was absent;
    # agent/sx-sec-domains registers it (along with armor_rules,
    # hier_firewall_rules, the perimeter tables and proposed_firewall_rules), so
    # the fixture would have COMPILED and this abstain path would have stopped
    # being exercised at all. `dns_policies` is a collection no domain module
    # registers, which is what keeps the path covered.
    unregistered = by_id["unregistered-collection"]
    assert unregistered.ast is None
    assert "dns_policies" in unregistered.error
    assert "not registered" in unregistered.error

    # cel parses CLEANLY here: the parser and sec_ast both accept cel; only
    # sec_encode refuses it, so rejecting at parse time would be the wrong layer.
    cel = by_id["cel-bearing-promise"]
    assert cel.ast is not None
    assert cel.error == ""

    for name in ("unsatisfiable-promise", "tautological-promise", "hallucinated-role"):
        assert by_id[name].error == "", name
        assert by_id[name].ast is not None, name

    # A hallucinated vocabulary reference is recorded, not grounded, by the parser.
    assert ("role", "roles/bigquery.reader") in by_id["hallucinated-role"].vocab

    # source.line pins each prose sentence to its literal line in the fixture.
    assert by_id["unsatisfiable-promise"].line == 13
    assert by_id["tautological-promise"].line == 27
    assert by_id["hallucinated-role"].line == 41
    assert by_id["unregistered-collection"].line == 55
    assert by_id["cel-bearing-promise"].line == 69


@pytest.mark.parametrize("name", ["iam.md", "orgpolicy.md", "degenerate.md"])
def test_every_parsed_ast_is_its_own_canonical(name):
    doc = m.parse_file(SEC / name)
    seen = 0
    for cand in doc.candidates:
        if cand.ast is not None:
            assert cand.ast == sec_ast.canonical(cand.ast)
            seen += 1
    assert seen  # each corpus doc has at least one cleanly-parsed AST


# -- inline documents: each documented failure mode ---------------------------

def _doc(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return m.parse_file(path)


def _only(doc):
    assert len(doc.candidates) == 1
    return doc.candidates[0]


def test_tab_inside_a_promise_block_is_a_candidate_error(tmp_path):
    doc = _doc(tmp_path, "tab.md", (
        "## Section\n\nProse.\n\n```promise\n"
        "id: has-tab\nmode: refute\nsmt:\n\texists b in iam_bindings\n"
        "    cmp eq field b.role str \"roles/owner\"\n```\n"))
    cand = _only(doc)
    assert cand.ast is None
    assert "tab" in cand.error


def test_odd_indent_line_is_a_candidate_error(tmp_path):
    doc = _doc(tmp_path, "odd.md", (
        "## Section\n\nProse.\n\n```promise\n"
        "id: odd-indent\nmode: refute\nsmt:\n exists b in iam_bindings\n"
        "   cmp eq field b.role str \"roles/owner\"\n```\n"))
    cand = _only(doc)
    assert cand.ast is None
    assert "multiple of two spaces" in cand.error


def test_unknown_header_key_names_it(tmp_path):
    doc = _doc(tmp_path, "hdr.md", (
        "## Section\n\nProse.\n\n```promise\n"
        "id: bad-header\nmode: refute\nbogus: nope\nsmt:\n"
        "  exists b in iam_bindings\n    cmp eq field b.role str \"roles/owner\"\n```\n"))
    cand = _only(doc)
    assert cand.ast is None
    assert "bogus" in cand.error


def test_missing_id_is_a_candidate_error(tmp_path):
    doc = _doc(tmp_path, "noid.md", (
        "## Section\n\nProse.\n\n```promise\n"
        "mode: refute\nsmt:\n  exists b in iam_bindings\n"
        "    cmp eq field b.role str \"roles/owner\"\n```\n"))
    cand = _only(doc)
    assert cand.id == ""
    assert "id" in cand.error


def test_duplicate_id_is_a_document_problem_and_both_candidates_error(tmp_path):
    doc = _doc(tmp_path, "dup.md", (
        "## First\n\nProse one.\n\n```promise\n"
        "id: dup\nmode: refute\nsmt:\n  exists b in iam_bindings\n"
        "    cmp eq field b.role str \"roles/owner\"\n```\n\n"
        "## Second\n\nProse two.\n\n```promise\n"
        "id: dup\nmode: refute\nsmt:\n  exists b in iam_bindings\n"
        "    cmp eq field b.role str \"roles/editor\"\n```\n"))
    assert any("duplicate id" in p and "dup" in p for p in doc.problems)
    assert len(doc.candidates) == 2
    for cand in doc.candidates:
        assert cand.id == "dup"
        assert cand.error != ""


def test_unterminated_fence_raises_parse_error(tmp_path):
    path = tmp_path / "open.md"
    path.write_text("## Section\n\nProse.\n\n```promise\nid: open\nmode: refute\n",
                    encoding="utf-8")
    with pytest.raises(ParseError):
        m.parse_file(path)


def test_unknown_smt_keyword_is_a_candidate_error(tmp_path):
    doc = _doc(tmp_path, "kw.md", (
        "## Section\n\nProse.\n\n```promise\n"
        "id: bad-kw\nmode: refute\nsmt:\n  exists b in iam_bindings\n"
        "    frobnicate field b.role str \"roles/owner\"\n```\n"))
    cand = _only(doc)
    assert cand.ast is None
    assert "frobnicate" in cand.error


def test_wrong_arity_is_a_candidate_error(tmp_path):
    # `not` takes exactly one child; give it two.
    doc = _doc(tmp_path, "arity.md", (
        "## Section\n\nProse.\n\n```promise\n"
        "id: bad-arity\nmode: refute\nsmt:\n  not\n"
        "    cmp eq field b.role str \"roles/owner\"\n"
        "    cmp eq field b.role str \"roles/editor\"\n```\n"))
    cand = _only(doc)
    assert cand.ast is None
    assert "not" in cand.error and "child" in cand.error


def test_unrecognized_frontmatter_key_is_a_document_problem(tmp_path):
    doc = _doc(tmp_path, "fm.md", (
        "---\ndomain: iam\nbogus_key: value\n---\n\n"
        "## Section\n\nProse.\n\n```promise\n"
        "id: fm-ok\nmode: refute\nsmt:\n  exists b in iam_bindings\n"
        "    cmp eq field b.role str \"roles/owner\"\n```\n"))
    assert any("bogus_key" in p for p in doc.problems)
    # The unrecognized key is not usable, but the promise still parses.
    cand = _only(doc)
    assert cand.error == ""
    assert cand.headers["domain"] == "iam"


def test_unrecognized_byte_in_the_term_language_raises_parse_error(tmp_path):
    path = tmp_path / "byte.md"
    path.write_text(
        "## Section\n\nProse.\n\n```promise\n"
        "id: bad-byte\nmode: refute\nsmt:\n  exists b in iam_bindings\n"
        "    cmp eq field b.role %\n```\n", encoding="utf-8")
    with pytest.raises(ParseError):
        m.parse_file(path)


# -- determinism --------------------------------------------------------------

def test_parse_text_is_byte_deterministic():
    text = (SEC / "iam.md").read_text(encoding="utf-8")
    assert m.parse_text(text, "iam.md") == m.parse_text(text, "iam.md")


def test_parse_file_sha256_is_over_the_raw_bytes():
    import hashlib
    raw = (SEC / "iam.md").read_bytes()
    doc = m.parse_file(SEC / "iam.md")
    assert doc.sha256 == hashlib.sha256(raw).hexdigest()
