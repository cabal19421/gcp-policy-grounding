"""The stdlib-only HCL2 subset reader, driven from the committed corpus.

Every assertion here is about the one property that makes a hand-written parser
safer than ``python-hcl2``: it either resolves a value or SAYS IT CANNOT. A
parser that silently mis-decodes an expression into a string that looks literal
manufactures a claim, and the gate then answers ``ungrounded`` about a role
name, a CIDR or a network that terraform never intended to exist. So the tests
that matter are the negative ones — the partial interpolation that must not
survive as a role name, the list that must not silently shrink, the truncated
file that must not yield a partial body, and the source scan that keeps
``eval``, ``exec`` and ``compile`` out of a module fed attacker-adjacent text.

``main.tf`` is the corpus's FULLY RESOLVABLE half and is pinned here from the
reader's side: zero notes and zero unresolved attributes, so a future
abstention on it is a reader bug and cannot be blamed on the fixture.
``unresolvable.tf`` is pinned from the other side, construct by construct,
against the reason each construct's own comment states.

`terraform` is not installed on this machine and nothing here needs it.
Degenerate and malformed inputs are built in ``tmp_path`` per the suite
convention; the two committed files stay positive fixtures.
"""

import ast
from pathlib import Path

import pytest

from gcp_grounding import facts
from gcp_grounding.tfsource import hcl_lite

HCL_DIR = Path(__file__).parent / "fixtures" / "gcp" / "tf" / "hcl"
MAIN_TF = HCL_DIR / "main.tf"
UNRESOLVABLE_TF = HCL_DIR / "unresolvable.tf"


def attribute_spans(body, prefix=""):
    """Every attribute in a body and its nested blocks, as ``(path, span)``."""
    for name, span in body.attributes.items():
        yield prefix + name, span
    for block in body.blocks:
        label = ".".join((block.type,) + block.labels)
        yield from attribute_spans(block.body, f"{prefix}{label}.")
    for label, blocks in body.dynamic.items():
        for block in blocks:
            yield from attribute_spans(block.body, f"{prefix}dynamic.{label}.")


def resources(body):
    """``"type.name" -> Block`` for the ``resource`` blocks in a body."""
    return {".".join(block.labels): block
            for block in body.blocks if block.type == "resource"}


@pytest.fixture(scope="module")
def main_body():
    parsed = hcl_lite.parse_file(MAIN_TF)
    return parsed.body


@pytest.fixture(scope="module")
def unresolvable():
    return resources(hcl_lite.parse_file(UNRESOLVABLE_TF).body)


def classify(block, attribute):
    return hcl_lite.classify_expr(block.body.attributes[attribute],
                                  f"values.{attribute}")


# -- main.tf: the fully resolvable half -----------------------------------


def test_main_tf_parses_with_zero_notes():
    parsed = hcl_lite.parse_file(MAIN_TF)
    assert parsed.notes == (), (
        "main.tf is well-formed HCL describing the corpus's one resolvable "
        "estate; a note on it means the reader refused a construct the fixture "
        "is pinned to contain")
    assert len(parsed.body.blocks) == 20


def test_main_tf_has_zero_unresolved_attributes(main_body):
    unresolved = {path: value
                  for path, span in attribute_spans(main_body)
                  for value in [hcl_lite.classify_expr(span, f"values.{path}")]
                  if facts.is_unresolved(value)}
    assert unresolved == {}, (
        "main.tf carries no interpolation, no variable reference, no count, no "
        "for_each, no dynamic block and no heredoc, so a reader that abstains "
        "on any part of it has a real bug and nothing to blame the fixture for")


def test_main_tf_folds_a_repeated_block_without_raising(main_body):
    """A REPEATED block is legal HCL and must not raise — unlike a duplicate
    attribute. The provider spells each protocol/ports pair as its own block, so
    a reader that kept only the first (or the last) loses a port silently."""
    health_checks = resources(main_body)["google_compute_firewall.allow_health_checks"]
    allows = [block for block in health_checks.body.blocks if block.type == "allow"]
    assert len(allows) == 2
    assert [hcl_lite.classify_expr(block.body.attributes["ports"], "values.ports")
            for block in allows] == [["80"], ["443"]]


def test_the_escaped_quote_attribute_round_trips(main_body):
    edge_waf = resources(main_body)["google_compute_security_policy.edge_waf"]
    rule = next(block for block in edge_waf.body.blocks if block.type == "rule")
    assert classify(rule, "description") == 'Block the "noisy scanner" range'


def test_literal_scalars_decode_to_python_values(main_body):
    vpc = resources(main_body)["google_compute_network.vpc_main"]
    assert classify(vpc, "name") == "vpc-main"
    assert classify(vpc, "auto_create_subnetworks") is False
    firewall = resources(main_body)["google_compute_firewall.allow_internal"]
    assert classify(firewall, "priority") == 1000
    assert classify(firewall, "source_ranges") == ["10.0.0.0/8"]


def test_a_trailing_comma_is_not_a_phantom_element(main_body):
    health_checks = resources(main_body)["google_compute_firewall.allow_health_checks"]
    assert classify(health_checks, "source_ranges") == ["35.191.0.0/16", "130.211.0.0/22"]


# -- unresolvable.tf: one construct per class, one assertion each ----------

# Each row is one construct in unresolvable.tf and the reason THE CONSTRUCT'S
# OWN COMMENT states, classified straight out of the expression span.
CLASSIFIED_CONSTRUCTS = [
    ("whole-value interpolation",
     "google_compute_firewall.whole_value_interpolation", "name", "interpolation"),
    ("partial interpolation",
     "google_project_iam_binding.partial_interpolation", "role", "interpolation"),
    ("local value",
     "google_compute_firewall.local_reference", "network", "interpolation"),
    ("data source attribute",
     "google_compute_firewall.data_reference", "project", "interpolation"),
    ("another resource's id",
     "google_compute_firewall.resource_reference", "network", "interpolation"),
    ("module output",
     "google_compute_subnetwork.module_reference", "network", "interpolation"),
    ("splat expression",
     "google_compute_firewall.splat_reference", "source_tags", "interpolation"),
    ("format()",
     "google_compute_firewall.function_calls", "name", "function_call"),
    ("cidrsubnet() inside a list",
     "google_compute_firewall.function_calls", "source_ranges", "function_call"),
    ("jsonencode()",
     "google_project_iam_policy.encoded_policy", "policy_data", "function_call"),
    ("templatefile()",
     "google_access_context_manager_access_level.templated", "title", "function_call"),
    ("indented heredoc",
     "google_project_iam_policy.heredoc_policy", "policy_data", "heredoc"),
    ("one interpolated attribute among literal siblings",
     "google_compute_firewall.mixed_granularity", "source_ranges", "interpolation"),
]


def test_unresolvable_tf_itself_parses_cleanly():
    """It is a POSITIVE fixture: well-formed HCL describing plausible
    terraform. Nothing in it resolves, and that is not the same as it failing
    to parse."""
    parsed = hcl_lite.parse_file(UNRESOLVABLE_TF)
    assert parsed.notes == ()
    assert len(parsed.body.blocks) == 27


@pytest.mark.parametrize("construct, address, attribute, reason",
                         CLASSIFIED_CONSTRUCTS,
                         ids=[row[0] for row in CLASSIFIED_CONSTRUCTS])
def test_each_construct_classifies_to_its_stated_reason(unresolvable, construct,
                                                        address, attribute, reason):
    value = classify(unresolvable[address], attribute)
    assert facts.is_unresolved(value), (
        f"{address}.{attribute} is the {construct} construct and must not "
        f"resolve to a value; emitting one manufactures a claim about a value "
        f"terraform never intended")
    assert value.reason == reason
    assert value.path == f"values.{attribute}"


def test_one_unresolvable_attribute_does_not_poison_its_siblings(unresolvable):
    """The attribute-granularity rule: a reader that abandoned the whole
    resource would throw away the two facts it actually has."""
    mixed = unresolvable["google_compute_firewall.mixed_granularity"]
    assert classify(mixed, "priority") == 900
    assert classify(mixed, "direction") == "INGRESS"
    assert facts.is_unresolved(classify(mixed, "source_ranges"))


# The four meta-argument constructs. Their stated reason is decided by the
# ATTRIBUTE NAME rather than by the expression, so hcl_lite parses them as
# ORDINARY attributes and the caller (tfsource/hcl.py) mints the reason. What
# this layer owes is that the construct SURVIVES the parse and that its value is
# never guessed at — a silently dropped meta-argument reads as a resource that
# is simply not multiplied.


def test_count_survives_as_an_ordinary_attribute(unresolvable):
    """reason: count — minted by the caller from the name."""
    counted = unresolvable["google_compute_firewall.counted"]
    assert "count" in counted.body.attributes
    assert facts.is_unresolved(classify(counted, "count"))
    assert "count" in facts.UNRESOLVED_REASONS


def test_for_each_survives_as_an_ordinary_attribute(unresolvable):
    """reason: for_each — minted by the caller from the name."""
    fanned = unresolvable["google_compute_firewall.fanned_out"]
    assert "for_each" in fanned.body.attributes
    assert facts.is_unresolved(classify(fanned, "for_each"))
    assert "for_each" in facts.UNRESOLVED_REASONS


def test_provider_alias_survives_as_an_ordinary_attribute(unresolvable):
    """reason: provider_alias — minted by the caller from the name."""
    aliased = unresolvable["google_compute_firewall.aliased"]
    assert "provider" in aliased.body.attributes
    assert facts.is_unresolved(classify(aliased, "provider"))
    assert "provider_alias" in facts.UNRESOLVED_REASONS


def test_missing_project_is_visible_as_an_absent_attribute(unresolvable):
    """reason: missing_project — the network is a BARE name and there is no
    project attribute at all, so the caller can see the key cannot be built."""
    bare = unresolvable["google_compute_firewall.bare_network"]
    assert "project" not in bare.body.attributes
    assert classify(bare, "network") == "default"
    assert "missing_project" in facts.UNRESOLVED_REASONS


# -- the partial-interpolation rule ---------------------------------------


def _span(source):
    """The expression span of the single attribute in a one-line body."""
    return hcl_lite.parse(source).attributes["a"]


def test_partial_interpolation_is_unresolved_because_the_check_is_a_substring():
    """`"roles/${var.tier}.admin"` starts with a literal and ends with one. A
    prefix check would emit it as a literal ROLE NAME and produce a guaranteed
    false `ungrounded` against a value terraform never intended to exist."""
    value = hcl_lite.classify_expr(_span('a = "roles/${var.tier}.admin"\n'))
    assert facts.is_unresolved(value)
    assert value.reason == "interpolation"


def test_the_escaped_dollar_brace_form_is_also_refused():
    """`$${` is HCL's escape for a literal `${`, and it is refused anyway —
    deliberately conservative. Mistaking an escaped literal for an
    interpolation costs one honest abstention; mistaking an interpolation for a
    literal costs a false verdict about a name nobody wrote."""
    value = hcl_lite.classify_expr(_span('a = "$${var.tier}"\n'))
    assert facts.is_unresolved(value)
    assert value.reason == "interpolation"


def test_a_marker_detail_never_carries_the_string_it_came_from():
    value = hcl_lite.classify_expr(_span('a = "roles/${var.tier}.admin"\n'))
    assert "roles/" not in value.detail
    assert "roles/" not in repr(value)


# -- a list is wholly unresolved, never shortened -------------------------


def test_a_list_with_one_function_call_is_wholly_unresolved():
    """A partially decoded list silently SHRINKS a rule's reach, and a check
    would then pass on a rule that does not exist."""
    value = hcl_lite.classify_expr(
        _span('a = ["10.0.0.0/8", cidrsubnet("10.0.0.0/8", 8, 3)]\n'))
    assert facts.is_unresolved(value)
    assert value.reason == "function_call"


def test_a_list_with_one_interpolated_element_is_wholly_unresolved():
    value = hcl_lite.classify_expr(_span('a = ["10.0.0.0/8", "${var.cidr}"]\n'))
    assert facts.is_unresolved(value)
    assert value.reason == "interpolation"


def test_a_list_with_one_bare_reference_is_wholly_unresolved():
    value = hcl_lite.classify_expr(_span('a = ["10.0.0.0/8", local.net]\n'))
    assert facts.is_unresolved(value)
    assert value.reason == "interpolation"


# -- the lexer ------------------------------------------------------------


def test_all_three_comment_syntaxes_lex():
    source = ('# hash comment\n'
              '// double slash comment\n'
              '/* slash star\n'
              '   across two lines */\n'
              'a = 1\n')
    kinds = [token.kind for token in hcl_lite.tokenize(source)
             if token.kind != "NEWLINE"]
    assert kinds == ["IDENT", "PUNCT", "NUMBER", "EOF"]
    assert hcl_lite.classify_expr(_span(source)) == 1


def test_both_heredoc_forms_lex_as_one_token_each():
    source = ('a = <<EOT\n'
              'plain body\n'
              'EOT\n'
              'b = <<-EOT\n'
              '  indented body\n'
              '  EOT\n')
    heredocs = [token for token in hcl_lite.tokenize(source) if token.kind == "HEREDOC"]
    assert len(heredocs) == 2
    assert heredocs[0].text == "plain body"
    assert heredocs[1].text == "indented body"
    body = hcl_lite.parse(source)
    for name in ("a", "b"):
        value = hcl_lite.classify_expr(body.attributes[name], f"values.{name}")
        assert facts.is_unresolved(value) and value.reason == "heredoc"


def test_the_four_hex_unicode_escape_decodes():
    assert hcl_lite.classify_expr(_span('a = "caf\\u00e9"\n')) == "café"


def test_a_token_carries_a_line_and_a_column():
    tokens = hcl_lite.tokenize('a = 1\n  b = 2\n')
    second = [token for token in tokens if token.kind == "IDENT"][1]
    assert (second.line, second.column) == (2, 3)


def test_an_unknown_character_raises_with_a_line_and_a_column():
    with pytest.raises(hcl_lite.HclSyntaxError) as caught:
        hcl_lite.tokenize('a = 1\nb = @\n')
    assert (caught.value.line, caught.value.column) == (2, 5)


# -- attributes and blocks ------------------------------------------------


def test_a_duplicate_attribute_raises_with_a_line_and_a_column():
    """Real terraform rejects a body that sets one attribute twice, so
    accepting it would mean answering about a configuration terraform would
    never apply — and inventing which of the two wins."""
    source = ('resource "google_compute_firewall" "dup" {\n'
              '  name = "a"\n'
              '  name = "b"\n'
              '}\n')
    with pytest.raises(hcl_lite.HclSyntaxError) as caught:
        hcl_lite.parse(source)
    assert (caught.value.line, caught.value.column) == (3, 3)
    assert "duplicate attribute" in caught.value.message


def test_a_repeated_block_does_not_raise():
    source = ('resource "google_compute_firewall" "twice" {\n'
              '  allow { protocol = "tcp" }\n'
              '  allow { protocol = "udp" }\n'
              '}\n')
    block = resources(hcl_lite.parse(source))["google_compute_firewall.twice"]
    assert [inner.type for inner in block.body.blocks] == ["allow", "allow"]


def test_a_dynamic_block_label_lands_in_dynamic_and_not_in_blocks(unresolvable):
    """A `dynamic "rule"` beside one static `rule` block would otherwise make
    the body look like it has exactly one rule, and a caller would conclude no
    permissive rule exists — a silent false negative on precisely the checks
    that matter."""
    mixed = unresolvable["google_compute_security_policy.mixed_rules"]
    assert "rule" in mixed.body.dynamic
    assert len(mixed.body.dynamic["rule"]) == 1
    assert [inner.type for inner in mixed.body.blocks] == ["rule"]
    assert "dynamic" not in [inner.type for inner in mixed.body.blocks]
    # The one STATIC rule is still there, and still resolves.
    static_rule = mixed.body.blocks[0]
    assert hcl_lite.classify_expr(static_rule.body.attributes["priority"],
                                  "values.rule[0].priority") == 1000


def test_a_dynamic_block_without_a_label_is_refused():
    with pytest.raises(hcl_lite.HclSyntaxError):
        hcl_lite.parse('resource "google_compute_firewall" "x" {\n'
                       '  dynamic {\n'
                       '    for_each = []\n'
                       '  }\n'
                       '}\n')


# -- parse_file never raises ----------------------------------------------


def test_an_empty_file_yields_the_empty_file_note(tmp_path):
    """So parsed-fine-nothing-here is distinguishable from
    parsed-fine-no-google-resources."""
    path = tmp_path / "empty.tf"
    path.write_text("", encoding="utf-8")
    parsed = hcl_lite.parse_file(path)
    assert parsed.notes == (hcl_lite.EMPTY_FILE_NOTE,)
    assert parsed.body.is_empty()


def test_a_truncated_file_yields_a_syntax_note_and_no_partial_body(tmp_path):
    """A half-parsed body is the same hazard as a mis-decoded value: it looks
    like a complete reading of a file and is not."""
    path = tmp_path / "truncated.tf"
    path.write_text('resource "google_compute_firewall" "t" {\n'
                    '  name = "t"\n', encoding="utf-8")
    parsed = hcl_lite.parse_file(path)
    assert len(parsed.notes) == 1
    assert parsed.notes[0].startswith(hcl_lite.SYNTAX_NOTE_PREFIX)
    assert parsed.body.is_empty()
    assert parsed.body.blocks == ()


def test_a_non_utf8_file_yields_an_encoding_note(tmp_path):
    path = tmp_path / "latin1.tf"
    path.write_bytes(b'resource "google_compute_firewall" "\xff\xfe" {}\n')
    parsed = hcl_lite.parse_file(path)
    assert len(parsed.notes) == 1
    assert parsed.notes[0].startswith(hcl_lite.ENCODING_NOTE_PREFIX)
    assert parsed.body.is_empty()


def test_an_unreadable_path_yields_a_read_note(tmp_path):
    parsed = hcl_lite.parse_file(tmp_path / "does-not-exist.tf")
    assert len(parsed.notes) == 1
    assert parsed.notes[0].startswith(hcl_lite.READ_NOTE_PREFIX)
    assert parsed.body.is_empty()
    # A directory is an OSError too, on the same arm.
    assert hcl_lite.parse_file(tmp_path).notes[0].startswith(hcl_lite.READ_NOTE_PREFIX)


def test_a_500_deep_nesting_returns_a_note_rather_than_raising(tmp_path):
    """The depth cap, not the interpreter's stack, is what bounds this. A
    RecursionError inside a gate is a gate that decided nothing."""
    depth = 500
    source = ('resource "google_compute_firewall" "deep" {\n'
              + "a {\n" * depth + "}" * depth + "\n}\n")
    path = tmp_path / "deep.tf"
    path.write_text(source, encoding="utf-8")
    parsed = hcl_lite.parse_file(path)
    assert len(parsed.notes) == 1
    assert parsed.notes[0].startswith(hcl_lite.DEPTH_NOTE_PREFIX)
    assert parsed.body.is_empty()
    with pytest.raises(hcl_lite.HclDepthError):
        hcl_lite.parse(source)
    assert issubclass(hcl_lite.HclDepthError, hcl_lite.HclSyntaxError)


def test_a_deeply_nested_expression_degrades_rather_than_recursing():
    depth = 500
    value = hcl_lite.classify_expr(
        _span("a = " + "[" * depth + "1" + "]" * depth + "\n"), "values.a")
    assert facts.is_unresolved(value)
    assert value.reason == "depth_cap"


# -- the prohibition, asserted over this module's own text ----------------

FORBIDDEN_CALLS = frozenset({"eval", "exec", "compile", "__import__",
                             "import_module", "load_module", "literal_eval"})


def test_the_module_never_evals_execs_or_compiles():
    """Not a style rule. This module is fed text an agent may have written, and
    the whole safety argument is that the text is scanned, never run."""
    source = Path(hcl_lite.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    called = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            called.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            called.add(node.func.attr)
    assert not called & FORBIDDEN_CALLS, sorted(called & FORBIDDEN_CALLS)
    for spelling in ("eval(", "exec(", "compile(", "__import__"):
        assert spelling not in source


def test_the_module_never_imports_anything_named_by_the_input():
    source = Path(hcl_lite.__file__).read_text(encoding="utf-8")
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not any(name.split(".")[0] == "importlib" for name in imported), sorted(imported)


def test_the_dependency_decision_is_stated_in_the_opening_docstring():
    """The four reasons python-hcl2 is rejected live in the docstring, not in a
    commit message, because the next person to reach for a dependency reads the
    module and not the history."""
    opening = (hcl_lite.__doc__ or "").split("\n\n")[1]
    assert "python-hcl2" in opening
    for reason in ("dependencies = []", "lark", "STRINGS THAT LOOK LITERAL",
                   "PARSES-BUT-SUBTLY-MIS-DECODES"):
        assert reason in opening
    assert "DOES-NOT-PARSE-THEREFORE-ABSTAINS" in opening


def test_every_reason_this_module_mints_is_in_the_closed_vocabulary():
    """A free-text reason is a reason nobody can grep for, and a typo'd one is a
    category of ignorance that silently never appears in a report."""
    minted = {"heredoc", "interpolation", "function_call", "unparsed", "depth_cap"}
    assert minted <= facts.UNRESOLVED_REASONS
