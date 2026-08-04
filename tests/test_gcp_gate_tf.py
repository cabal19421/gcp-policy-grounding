"""Acceptance for the gate's TERRAFORM routing: when an agent edits terraform,
the PROPOSAL is terraform — HCL as a proposal, state as a source, never confused.

Capability is branched on with plain module-level booleans (the ``HAVE_Z3``
idiom) and never ``skipif``, so an absent capability is asserted to degrade
honestly rather than being quietly passed over.

The load-bearing tests, and the failure each one guards:

- :func:`test_both_encodings_produce_the_same_triples` and
  :func:`test_the_zero_dependency_walker_agrees_with_the_shipped_reader` — the
  ONE HCL-to-claims path. ``.tf.json`` is walked with ``json.load`` and no
  parser at all, so nothing about the gate depends on ``tfsource``; the pins
  are that the encoding never changes the triples and that the walker's answer
  is the shipped reader's answer, attribute for attribute.
- :func:`test_an_interpolation_never_becomes_a_claim_value` — the whole point
  of stripping. A ``${var.x}`` emitted as a literal is a guaranteed false
  verdict about a name nobody wrote, so the serialized result is searched for
  the dollar-brace literal outright.
- :func:`test_two_interpolations_yield_exactly_two_unresolved_verdicts` — THE
  ASSEMBLE-THEN-PREPARE PIN. Building the plan first and calling
  ``prepare_proposal`` ONCE is what single-sources the ``unresolved`` tuple.
  Calling it per block body yields N throwaway proposals whose tuples an
  implementer is free to drop while keeping the sanitized documents — and
  dropping them loses the downgrade entirely, turning an interpolated firewall
  into a clean pass. Exactly two paths, address-prefixed, and every
  ``grounded`` downgraded, is what proves the tuples reached the final
  proposal.
- :func:`test_a_tf_json_widening_reaches_the_pair_tier` — the point of routing
  terraform at all: a ``.tf.json`` edit is compared against a configured
  terraform-state baseline by the same pair tier every other proposal uses.
- :func:`test_a_stub_dynamic_path_downgrades_every_grounded` — the HCL hazard.
  A ``dynamic`` block means the enumerated blocks are a SUBSET of the real
  ones, so a resource whose rule set may be truncated must never produce a
  conclusion that no permissive rule exists.
- :func:`test_a_tfstate_says_exactly_the_shared_constant` — THE ANTI-DRIFT PIN
  against the CLI's copy. Three entry points sniff the same file; a drifted
  message (or a drifted sniff) is exactly the zero-claim clean pass the state
  arm exists to close.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import shutil
import sys
import types
from pathlib import Path

import pytest

from gcp_grounding import facts, gate, sources
from gcp_grounding.gate import PolicyGroundingGate
from gcp_grounding.sources import SourceOptions

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
HCL_DIR = FIXTURES / "tf" / "hcl"
ESTATE = FIXTURES / "estate_snapshot.json"
TFSTATE = FIXTURES / "tf" / "estate.tfstate"

#: Two days after every fixture's ``captured_at`` — inside the age ceiling, so
#: the run is deterministic whatever the wall clock says.
FRESH = "2026-07-20T09:30:00Z"

#: The resource ``main.tf`` and the LIST-encoded ``perimeter.tf.json`` share,
#: attribute for attribute.
SHARED = "google_access_context_manager_service_perimeter.prod"

HAVE_HCL = importlib.util.find_spec("gcp_grounding.tfsource.hcl") is not None
HAVE_DISCOVER = (importlib.util.find_spec("gcp_grounding.tfsource.discover")
                 is not None)
#: Whether the VPC-firewall domain module is part of this checkout. The pair
#: tier reaches a firewall row either way; what the state can SAY about it is
#: what this branches.
HAVE_FW_DOMAIN = importlib.util.find_spec("gcp_grounding.fw_claims") is not None

if HAVE_DISCOVER:
    from gcp_grounding.tfsource import discover
if HAVE_HCL:
    from gcp_grounding.tfsource import hcl


# -- helpers ------------------------------------------------------------------


@contextlib.contextmanager
def blocked_import(*names: str):
    """Make *names* (and their submodules) unimportable for the block.

    The gate resolves the terraform readers LAZILY, so the absent-reader path
    is live code rather than a comment about a checkout nobody has. Blocking
    the import is how it is exercised — and how the inline last-resort v4 sniff
    is exercised too.
    """
    class Blocker:
        def find_spec(self, fullname, path=None, target=None):
            if fullname in names or any(fullname.startswith(f"{n}.")
                                        for n in names):
                raise ImportError(f"blocked for this test: {fullname}")
            return None

    saved = {name: module for name, module in list(sys.modules.items())
             if name in names or any(name.startswith(f"{n}.") for n in names)}
    for name in saved:
        del sys.modules[name]
    blocker = Blocker()
    sys.meta_path.insert(0, blocker)
    try:
        yield
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(saved)


def triples_of(path: Path) -> dict[str, tuple[str, object]]:
    """The gate's own ``.tf.json`` walk of *path*, keyed by address."""
    document = json.loads(path.read_text(encoding="utf-8"))
    return {address: (resource_type, values)
            for address, resource_type, values
            in gate._tf_json_triples(document, facts)}


def as_mapping_encoding(document: dict) -> dict:
    """The LIST-of-single-key-mappings ``resource`` block, re-spelled as the
    MAPPING encoding — the same configuration in terraform's other legal JSON
    syntax."""
    merged: dict[str, dict] = {}
    for entry in document["resource"]:
        for resource_type, named in entry.items():
            merged.setdefault(resource_type, {}).update(named)
    return dict(document, resource=merged)


def only(result) -> object:
    [file] = result.files
    return file


def kinds(file, status: str) -> list[str]:
    return [v.kind for v in file.verdicts if v.status == status]


def unresolved_targets(file) -> list[str]:
    return [v.target for v in file.verdicts if v.kind == "proposal:unresolved"]


@pytest.fixture()
def tf_gate() -> PolicyGroundingGate:
    """The estate snapshot as the vocabulary, and NO current state — the plain
    path every ``.tf``/``.tf.json`` assertion that is not about the pair tier
    runs on."""
    return PolicyGroundingGate(ESTATE)


# -- terraform's own JSON configuration syntax --------------------------------


def test_both_encodings_produce_the_same_triples():
    """A ``resource`` MAPPING and a ``resource`` LIST of single-key mappings are
    two spellings of one configuration, and both are committed as fixtures so
    neither is hypothetical. The encoding must not survive into the triples."""
    document = json.loads((HCL_DIR / "perimeter.tf.json").read_text(encoding="utf-8"))
    assert isinstance(document["resource"], list)        # the LIST encoding
    mapping_form = as_mapping_encoding(document)
    assert isinstance(mapping_form["resource"], dict)    # the MAPPING encoding

    from_list = gate._tf_json_triples(document, facts)
    from_mapping = gate._tf_json_triples(mapping_form, facts)
    assert from_list == from_mapping

    # And the committed MAPPING fixture walks to its own two addresses, so both
    # encodings are exercised by a file on disk and not only by a re-spelling.
    assert sorted(triples_of(HCL_DIR / "proposal.tf.json")) == [
        "google_compute_firewall.allow_ssh_world",
        "google_project_iam_binding.data_eng_owner",
    ]
    assert sorted(triples_of(HCL_DIR / "perimeter.tf.json")) == [
        SHARED, "google_compute_firewall.allow_internal",
    ]


def test_a_one_element_array_body_and_comment_keys_are_terraform_json_too():
    """The innermost value may be a LIST of blocks, and ``//`` is terraform's
    JSON comment at every level — neither is an attribute."""
    document = {
        "//": "a file-level comment",
        "resource": [{"google_project_iam_binding": {
            "//": "a type-level comment",
            "owner": [{"//": "a body-level comment",
                       "project": "acme-prod",
                       "role": "roles/owner",
                       "members": ["user:alice@acme.example"]}],
        }}],
    }
    [(address, resource_type, values)] = gate._tf_json_triples(document, facts)
    assert (address, resource_type) == ("google_project_iam_binding.owner",
                                        "google_project_iam_binding")
    assert values == {"project": "acme-prod", "role": "roles/owner",
                      "members": ["user:alice@acme.example"]}


def test_the_zero_dependency_walker_agrees_with_the_shipped_reader():
    """THERE IS EXACTLY ONE HCL-TO-CLAIMS PATH. The gate's ``json.load`` walk
    and :mod:`gcp_grounding.tfsource.hcl` must produce the same triple for the
    same resource, or the ``.tf`` and ``.tf.json`` arms are two readers."""
    if not HAVE_HCL:
        pytest.fail("gcp_grounding.tfsource.hcl is not part of this checkout — "
                    "the raw-.tf arm cannot be compared against it")
    from_json = triples_of(HCL_DIR / "perimeter.tf.json")
    from_hcl = {address: (resource_type, values) for address, resource_type, values
                in hcl.parse_config_file(HCL_DIR / "main.tf")[0]}
    assert from_json[SHARED] == from_hcl[SHARED]


# -- interpolations: stripped and REPORTED, never a claim value ---------------


def test_an_interpolation_never_becomes_a_claim_value(tf_gate):
    """``.tf.json`` still carries interpolations. One emitted as a literal is a
    guaranteed false verdict about a name terraform never intended to exist."""
    path = HCL_DIR / "proposal.tf.json"
    result = tf_gate.check([path])
    serialized = json.dumps(result.to_dict())
    assert "${" not in serialized
    assert "var.change_ticket" not in serialized

    file = only(result)
    assert file.policy_candidate
    assert unresolved_targets(file) == [
        "google_compute_firewall.allow_ssh_world.description"]


def test_two_interpolations_yield_exactly_two_unresolved_verdicts(tf_gate, tmp_path):
    """THE ASSEMBLE-THEN-PREPARE PIN — see the module docstring.

    Two resources, one interpolation each: exactly two ``proposal:unresolved``
    verdicts, both named by the PLAN's address and not by the source file's own
    JSON structure, and every ``grounded`` downgraded because part of the
    document could not be resolved.
    """
    body = {
        "name": "x", "project": "acme-prod",
        "network": "projects/acme-prod/global/networks/vpc-main",
        "direction": "INGRESS", "priority": 100, "disabled": False,
        "allow": [{"protocol": "tcp", "ports": ["22"]}],
        "source_ranges": ["0.0.0.0/0"],
    }
    path = tmp_path / "two.tf.json"
    path.write_text(json.dumps({"resource": {"google_compute_firewall": {
        "one": dict(body, description="${var.a}"),
        "two": dict(body, description="${var.b}"),
    }}}), encoding="utf-8")

    file = only(tf_gate.check([path]))
    assert unresolved_targets(file) == [
        "google_compute_firewall.one.description",
        "google_compute_firewall.two.description",
    ]
    # Plan-relative and address-prefixed: each path names the resource by its
    # terraform address and then the attribute — never by where the attribute
    # sat in the .tf.json, and never by the assembled plan's own structure.
    # ONE spelling is what keeps the tuple single-sourced: two would double
    # every path and put a second, differently worded verdict on one attribute.
    for target in unresolved_targets(file):
        assert target.startswith(("google_compute_firewall.one.",
                                  "google_compute_firewall.two."))
        assert target.rsplit(".", 1)[-1] == "description"
        assert not target.startswith("resource.")
        assert "planned_values" not in target and "root_module" not in target

    # THE DOWNGRADE. Both firewalls were grounded against the vocabulary; both
    # come back unverified, because a document part of which could not be
    # resolved cannot be claimed clean.
    assert kinds(file, "grounded") == []
    downgraded = [v for v in file.verdicts
                  if v.kind == "resource_type" and v.status == "unverified"]
    assert len(downgraded) == 2
    assert all("a clean result cannot be claimed" in v.message
               for v in downgraded)
    assert file.status == "unverified"


def test_a_tf_json_widening_reaches_the_pair_tier():
    """The point of routing terraform at all: a ``.tf.json`` edit is compared
    against a configured terraform-state baseline, by the SAME pair tier every
    other proposal reaches — no ``--baseline`` typed by a human."""
    options = SourceOptions(primary=str(ESTATE),
                            terraform_state=(str(TFSTATE),))
    current = sources.load_current(options)
    assert current.ok
    policy_gate = PolicyGroundingGate(ESTATE, current=current, options=options)
    file = only(policy_gate.check([HCL_DIR / "proposal.tf.json"], as_of=FRESH))

    # The IAM half of the fixture: a binding the estate does not carry, caught
    # by the built-in new⊆old comparison. That is the pair tier, reached.
    [subset] = [v for v in file.verdicts if v.kind == "subset"]
    assert "roles/owner" in subset.message
    assert "group:data-eng@acme.example" in subset.message

    # The firewall half. `allow-ssh-world` opens tcp/22 to 0.0.0.0/0, and the
    # pair tier asks the current state for its counterpart either way; what the
    # state can ANSWER is what the domain module decides.
    firewall = [v for v in file.verdicts
                if "allow-ssh-world" in v.target or "allow-ssh-world" in v.message]
    assert firewall, "the pair tier never asked about the firewall row"
    if not HAVE_FW_DOMAIN:
        # Honest abstention with a stated reason, never a silent skip.
        [unqueried] = [v for v in firewall if v.kind == "baseline:unqueried"]
        assert "firewall_rules" in unqueried.message
    else:
        assert any(v.kind != "baseline:unqueried" for v in firewall)


# -- raw HCL ------------------------------------------------------------------


def test_the_real_reader_routes_a_raw_tf_to_the_same_claims_as_its_tf_json_twin(
        tf_gate):
    """With the reader importable, ``main.tf`` routes through it and produces
    the same claim set for the resource it shares with the LIST-encoded
    ``.tf.json`` — one pipeline, two spellings of its input."""
    if not HAVE_HCL:
        pytest.fail("gcp_grounding.tfsource.hcl is not part of this checkout")

    def claims_about(path: Path) -> set[tuple[str, str, str]]:
        file = only(tf_gate.check([path]))
        return {(v.kind, v.target, v.message.split(":")[0])
                for v in file.verdicts if v.message.startswith(f"{SHARED}.")
                or v.message.startswith(f"{SHARED}:")}

    from_hcl = claims_about(HCL_DIR / "main.tf")
    from_json = claims_about(HCL_DIR / "perimeter.tf.json")
    assert from_hcl and from_hcl == from_json


def test_a_clean_raw_tf_is_never_reported_as_a_clean_pass(tf_gate):
    """A static read of a terraform PROGRAM enumerates a SUBSET of what will be
    applied — variables, locals, functions, ``module`` blocks and the module's
    other files are not evaluated — so the file always reports one unresolved
    path and nothing on it is claimed clean.

    ``ungrounded`` and ``contradicted`` STAND, which is what keeps the routing
    worth doing: a hallucinated resource type in raw HCL still fails the gate.
    """
    if not HAVE_HCL:
        pytest.fail("gcp_grounding.tfsource.hcl is not part of this checkout")
    file = only(tf_gate.check([HCL_DIR / "main.tf"]))
    assert kinds(file, "grounded") == []
    assert f"{HCL_DIR / 'main.tf'}:<hcl-static-read>" in unresolved_targets(file)
    # The estate fixture's resource_types does not carry google_compute_network,
    # so the finding survives the downgrade and the file FAILS.
    assert file.status == "failed"
    assert any(v.kind == "resource_type" and "google_compute_network" in v.target
               for v in file.verdicts if v.status == "ungrounded")


def test_the_raw_tf_note_names_the_plan_and_the_estate_flags(tf_gate):
    """The terraform note: gate the plan (or the equivalent ``.tf.json``) for a
    complete view, and get terraform-derived ESTATE facts from the
    terraform-state and merge-source flags — never from the file under review."""
    if not HAVE_HCL:
        pytest.fail("gcp_grounding.tfsource.hcl is not part of this checkout")
    file = only(tf_gate.check([HCL_DIR / "main.tf"]))
    [note] = [v for v in file.verdicts
              if v.kind == "proposal:unresolved" and "terraform show -json" in v.message]
    assert ".tf.json" in note.message
    assert "terraform-state" in note.message and "merge-source" in note.message


def test_a_blocked_hcl_reader_leaves_the_file_an_unverified_candidate(tf_gate):
    """A checkout without the ``tfsource`` reader must DEGRADE, not fail. The
    absent-reader path stays live code and is exercised by blocking the import.
    """
    with blocked_import("gcp_grounding.tfsource.hcl"):
        result = tf_gate.check([HCL_DIR / "main.tf"])
    file = only(result)
    assert file.status == "unverified" and file.policy_candidate
    assert result.ok and result.risk == "low"
    [note] = file.verdicts
    assert note.message == gate._HCL_ABSENT_NOTE.format(path=str(HCL_DIR / "main.tf"))
    assert "HCL reader" in note.message and "terraform show -json" in note.message
    assert ".tf.json" in note.message
    assert "terraform-state" in note.message and "merge-source" in note.message


def test_a_stub_dynamic_path_downgrades_every_grounded(tf_gate, tmp_path,
                                                       monkeypatch):
    """A ``dynamic`` block generates blocks a static reader cannot see, so the
    enumerated ones are a SUBSET. The reader reports an unresolved path for the
    CONTAINING resource; the gate strips nothing and REPORTS it, and every
    ``grounded`` on the document becomes ``unverified``.

    A resource whose rule set may be truncated must never produce a conclusion
    that no permissive rule exists.
    """
    address = "google_compute_firewall.dynamic_allow"
    values = {
        "name": "dynamic-allow", "project": "acme-prod",
        "network": "projects/acme-prod/global/networks/vpc-main",
        "direction": "INGRESS", "priority": 1000, "disabled": False,
        "source_ranges": ["10.0.0.0/8"],
        "allow": [{"protocol": "tcp", "ports": ["22"]},
                  facts.Unresolved("dynamic_block", "allow[]",
                                   "a dynamic 'allow' block generates blocks "
                                   "this reader cannot see")],
    }
    stub = types.ModuleType("gcp_grounding.tfsource.hcl")
    stub.parse_config_file = lambda path: (
        ((address, "google_compute_firewall", values),), (f"{address}.allow[1]",))
    stub.parse_config_dir = stub.parse_config_file
    monkeypatch.setitem(sys.modules, "gcp_grounding.tfsource.hcl", stub)

    path = tmp_path / "dynamic.tf"
    path.write_text("# read by the stub\n", encoding="utf-8")
    file = only(tf_gate.check([path]))

    # The reader's path reached the FINAL proposal rather than being discarded.
    assert f"{address}.allow[1]" in unresolved_targets(file)
    assert kinds(file, "grounded") == []
    [resource_type] = [v for v in file.verdicts if v.kind == "resource_type"]
    assert resource_type.status == "unverified"
    assert "a clean result cannot be claimed" in resource_type.message


# -- .tfstate: a source, never a proposal -------------------------------------


def test_a_tfstate_says_exactly_the_shared_constant(tf_gate):
    """THE ANTI-DRIFT PIN. The gate, the CLI's ``verify-policy`` argument and
    the discovery classifier all meet the same file; the message is the SHARED
    constant so none of them can say something different about it."""
    if not HAVE_DISCOVER:
        pytest.fail("gcp_grounding.tfsource.discover is not part of this checkout")
    result = tf_gate.check([TFSTATE])
    file = only(result)
    assert file.status == "unverified" and file.policy_candidate
    assert result.ok and result.risk == "low"
    [note] = file.verdicts
    assert note.message == discover.STATE_NOT_A_PROPOSAL.format(path=str(TFSTATE))


def test_a_tfstate_is_never_graded_as_a_proposal(tf_gate):
    """Grading state would report the WHOLE ESTATE as if an agent had just
    written it, so not one role or member in the file becomes a claim."""
    state = json.loads(TFSTATE.read_text(encoding="utf-8"))
    assert "roles/" in json.dumps(state), "the fixture must carry IAM to be a test"

    file = only(tf_gate.check([TFSTATE]))
    assert [v.kind for v in file.verdicts] == ["document"]
    assert not [v for v in file.verdicts
                if v.kind in ("role", "principal", "permission", "resource_type")]


def test_the_tfstate_suffix_refuses_a_state_file_the_sniff_would_not_catch(
        tf_gate, tmp_path):
    """``.tfstate`` is refused by NAME, unconditionally. The content sniff is
    for state files that are NOT called ``.tfstate``; it is not what the suffix
    arm leans on, or a version-3 state — which no v4 sniff recognises — would
    be graded as a proposal after all."""
    path = tmp_path / "legacy.tfstate"
    path.write_text(json.dumps({"version": 3, "serial": 1,
                                "modules": [{"path": ["root"], "resources": {}}]}),
                    encoding="utf-8")
    if HAVE_DISCOVER:
        assert not discover.is_v4_state(json.loads(path.read_text(encoding="utf-8")))
    file = only(tf_gate.check([path]))
    assert file.policy_candidate and file.status == "unverified"
    assert "not a proposed change" in file.verdicts[0].message


def test_an_extensionless_v4_state_routes_through_the_shared_sniff(
        tf_gate, tmp_path, monkeypatch):
    """A ``terraform state pull > current`` is a state file whatever it is
    called. The sniff is :func:`tfsource.discover.is_v4_state` and NOT a local
    ``version == 4``: a fourth hand-written copy is a fourth place to drift, and
    a drifted sniff is exactly the zero-claim clean pass this arm closes."""
    if not HAVE_DISCOVER:
        pytest.fail("gcp_grounding.tfsource.discover is not part of this checkout")
    path = tmp_path / "current"
    shutil.copy(TFSTATE, path)

    file = only(tf_gate.check([path]))
    assert file.policy_candidate and file.status == "unverified"
    [note] = file.verdicts
    assert note.message == discover.STATE_NOT_A_PROPOSAL.format(path=str(path))

    # Driven THROUGH the shared predicate: teach it that nothing is state and
    # the same bytes stop reaching the state arm, which is what proves the gate
    # asks `discover.is_v4_state` rather than deciding for itself.
    monkeypatch.setattr(discover, "is_v4_state", lambda doc: False)
    [rerouted] = tf_gate.check([path]).files
    assert not rerouted.policy_candidate
    [other] = rerouted.verdicts
    assert "not a policy file" in other.message
    assert "not a proposed change" not in other.message


def test_the_inline_fallback_routes_a_state_file_with_tfsource_blocked(
        tf_gate, tmp_path):
    """The duplicate of last resort: with ``tfsource`` unimportable the gate
    still refuses to grade state as a proposal. ``discover.is_v4_state`` stays
    authoritative wherever it can be imported."""
    path = tmp_path / "current"
    shutil.copy(TFSTATE, path)
    with blocked_import("gcp_grounding.tfsource"):
        file = only(tf_gate.check([path]))
    assert file.policy_candidate and file.status == "unverified"
    [note] = file.verdicts
    assert note.message == gate._STATE_NOT_A_PROPOSAL_FALLBACK.format(path=str(path))
    if HAVE_DISCOVER:
        # Byte-identical to the authoritative constant, so the fallback cannot
        # be the place the wording drifts.
        assert (gate._STATE_NOT_A_PROPOSAL_FALLBACK
                == discover.STATE_NOT_A_PROPOSAL)


def test_a_state_file_that_is_already_a_source_says_so():
    """When the file under review IS one of the run's configured state sources,
    the message says so rather than telling the user to configure what they
    already configured."""
    if not HAVE_DISCOVER:
        pytest.fail("gcp_grounding.tfsource.discover is not part of this checkout")
    options = SourceOptions(primary=str(ESTATE),
                            terraform_state=(str(TFSTATE),))
    current = sources.load_current(options)
    policy_gate = PolicyGroundingGate(ESTATE, current=current, options=options)
    file = only(policy_gate.check([TFSTATE], as_of=FRESH))
    [note] = file.verdicts
    assert note.message.startswith(
        discover.STATE_NOT_A_PROPOSAL.format(path=str(TFSTATE)))
    assert note.message.endswith(gate._ALREADY_A_STATE_SOURCE)


# -- the routing table --------------------------------------------------------


def test_the_four_candidate_suffixes_are_matched_case_insensitively(tf_gate,
                                                                    tmp_path):
    """All four suffixes make a file a policy candidate by NAME alone, matched
    case-insensitively exactly as ``.policy.json`` always was."""
    assert gate._CANDIDATE_SUFFIXES == (".policy.json", ".tf.json", ".tf",
                                        ".tfstate")
    written = {
        "MAIN.TF": 'resource "google_project_iam_member" "x" {}\n',
        "Proposal.TF.JSON": json.dumps({"resource": {}}),
        "Estate.TFSTATE": TFSTATE.read_text(encoding="utf-8"),
    }
    paths = []
    for name, text in written.items():
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    result = tf_gate.check(paths)
    assert all(f.policy_candidate for f in result.files)
    assert result.ok and result.risk == "low"


def test_a_tf_json_that_is_not_valid_json_fails_open(tf_gate, tmp_path):
    """The fail-open contract holds on the terraform arms too."""
    path = tmp_path / "broken.tf.json"
    path.write_text("{not json", encoding="utf-8")
    result = tf_gate.check([path])
    file = only(result)
    assert result.ok and file.status == "unverified" and file.policy_candidate
    assert "not valid JSON" in "\n".join(result.findings())
