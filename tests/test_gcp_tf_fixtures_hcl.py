"""The one committed HCL corpus, pinned as FILES.

This module imports nothing from ``gcp_grounding.tfsource`` on purpose. It is
not a reader test: it is the pin that keeps the four fixture files honest for
every reader task that grounds against them, and it must keep passing even
before a reader exists.

The load-bearing assertion is the negative one. ``main.tf`` is the FULLY
RESOLVABLE fixture, and it is only fully resolvable because it contains no
interpolation, no variable reference, no ``count``, no ``for_each``, no
``dynamic`` block and no heredoc anywhere -- so a reader that abstains on any
part of it has a real bug and cannot blame the fixture. That property is easy
to weaken by accident (one convenience variable and it is gone), which is why
it is pinned here rather than left as a comment. Its twin, ``unresolvable.tf``,
is pinned from the other side: every unresolvable class the reader must
classify has to still be PRESENT in it.

``perimeter.tf.json`` and ``proposal.tf.json`` are the two legal terraform-JSON
encodings -- a ``resource`` LIST of single-key objects, and a ``resource``
MAPPING from type to name to body. Both are committed exactly once, and the
shapes are asserted to be genuinely different so a future edit cannot quietly
collapse the corpus onto one encoding and leave the other path untested.

`terraform` is not installed on this machine and nothing here requires it.
These are POSITIVE fixtures; degenerate and malformed inputs belong in
``tmp_path`` per the suite convention.
"""

import json
from pathlib import Path

import pytest

HCL_DIR = Path(__file__).parent / "fixtures" / "gcp" / "tf" / "hcl"
MAIN_TF = HCL_DIR / "main.tf"
UNRESOLVABLE_TF = HCL_DIR / "unresolvable.tf"
PERIMETER_JSON = HCL_DIR / "perimeter.tf.json"
PROPOSAL_JSON = HCL_DIR / "proposal.tf.json"

ALL_FIXTURES = (MAIN_TF, UNRESOLVABLE_TF, PERIMETER_JSON, PROPOSAL_JSON)

# Constructs that make a value unresolvable from configuration alone. NONE of
# them may appear in main.tf: that is what "fully resolvable" means.
FORBIDDEN_IN_MAIN = (
    "${",          # any interpolation, whole-value or embedded
    " var.",       # a variable reference
    "count ",      # the count meta-argument
    "for_each",    # the for_each meta-argument, and dynamic-block iterators
    "dynamic ",    # a dynamic block
    "<<",          # a heredoc, in either the plain or the indented form
)

# The unresolvable classes unresolvable.tf carries one construct each for.
REQUIRED_IN_UNRESOLVABLE = (
    "${var.",                        # interpolation of a variable
    "local.",                        # a local value
    "count ",                        # the count meta-argument
    "for_each",                      # the for_each meta-argument
    'dynamic "',                     # a dynamic block
    "format(",                       # a function call
    "<<-",                           # the indented heredoc marker
    "[*]",                           # a splat expression
    "google.eu",                     # an aliased provider
)

# The six domains main.tf covers, in the exact terraform provider spellings.
REQUIRED_IN_MAIN = (
    "google_compute_network",
    "google_compute_subnetwork",
    "google_compute_firewall",
    "google_compute_firewall_policy",
    "google_compute_firewall_policy_rule",
    "google_compute_firewall_policy_association",
    "google_compute_security_policy",
    "google_compute_security_policy_rule",
    "google_access_context_manager_service_perimeter",
    "google_access_context_manager_access_level",
    "google_project_iam_binding",
    "google_project_iam_member",
    "google_project_iam_custom_role",
    "google_service_account",
    "google_org_policy_policy",
)


def _read(path):
    return path.read_text(encoding="utf-8")


# -- all four files are there ---------------------------------------------


@pytest.mark.parametrize("path", ALL_FIXTURES, ids=lambda p: p.name)
def test_fixture_exists_and_is_non_empty(path):
    assert path.is_file(), f"{path} is missing"
    assert _read(path).strip(), f"{path} is empty"


# -- main.tf is fully resolvable, and stays that way ----------------------


@pytest.mark.parametrize("construct", FORBIDDEN_IN_MAIN)
def test_main_tf_has_no_unresolvable_construct(construct):
    assert construct not in _read(MAIN_TF), (
        f"main.tf contains {construct!r}. main.tf is the FULLY RESOLVABLE "
        f"fixture: a reader must resolve every object in it, with nothing to "
        f"excuse a missing record. Anything a static reader cannot resolve "
        f"belongs in unresolvable.tf, which is next door and exists for "
        f"exactly this.")


@pytest.mark.parametrize("resource_type", REQUIRED_IN_MAIN)
def test_main_tf_covers_every_domain(resource_type):
    assert resource_type in _read(MAIN_TF), (
        f"main.tf no longer mentions {resource_type!r}; it is the corpus's "
        f"single resolvable estate and has to cover all six domains.")


def test_main_tf_exercises_the_lexer():
    text = _read(MAIN_TF)
    assert "#" in text and "//" in text and "/*" in text, (
        "main.tf must carry comments in all three HCL syntaxes")
    assert '\\"' in text, "main.tf must carry one escaped quote in a value"
    assert '",\n  ]' in text, "main.tf must carry one trailing comma in a list"


# -- unresolvable.tf keeps one construct per class ------------------------


@pytest.mark.parametrize("construct", REQUIRED_IN_UNRESOLVABLE)
def test_unresolvable_tf_has_every_construct(construct):
    assert construct in _read(UNRESOLVABLE_TF), (
        f"unresolvable.tf no longer contains {construct!r}. Each construct "
        f"there stands for one unresolvable class the reader has to classify "
        f"by the reason its comment states; removing one silently retires "
        f"that class's coverage.")


# -- the two JSON encodings are genuinely different shapes ----------------


def test_perimeter_json_is_the_list_encoding():
    doc = json.loads(_read(PERIMETER_JSON))
    assert isinstance(doc["resource"], list), (
        "perimeter.tf.json is the LIST-of-single-key-objects encoding")
    types = [t for block in doc["resource"] for t in block]
    assert "google_access_context_manager_service_perimeter" in types
    assert "google_compute_firewall" in types


def test_proposal_json_is_the_mapping_encoding():
    doc = json.loads(_read(PROPOSAL_JSON))
    assert isinstance(doc["resource"], dict), (
        "proposal.tf.json is the type-to-name-to-body MAPPING encoding")
    assert "google_compute_firewall" in doc["resource"]
    assert "google_project_iam_binding" in doc["resource"]


def test_the_two_json_fixtures_do_not_share_an_encoding():
    perimeter = json.loads(_read(PERIMETER_JSON))["resource"]
    proposal = json.loads(_read(PROPOSAL_JSON))["resource"]
    assert type(perimeter) is not type(proposal), (
        "the corpus commits BOTH legal terraform-JSON encodings exactly once; "
        "collapsing them onto one shape leaves the other reader path untested")
