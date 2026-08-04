"""Acceptance for ``gcp_grounding.tfsource.discover``.

The load-bearing module here is THE NON-STEALING MATRIX. Discovery decides
which files become CURRENT-STATE evidence, and the repository's committed
policy fixtures are the other side of the engine — the documents under review.
A discoverer that picks one up turns a proposal into a source, grounds the
change against itself, and passes every widening check it should have caught.
So every one of the seven policy fixtures, the vocabulary snapshot, a
``package.json``-shaped document and a bare empty object are asserted REJECTED
WITH A REASON, one parametrised case each so a failure names the file that
leaked.

The second pin is the ``terraform_version`` trap, asserted side by side:
``preflight.detect_kind`` reads the committed v4 tfstate as a terraform PLAN,
because every tfstate carries ``terraform_version`` and that is one of its
plan keys. ``classify_path`` reads the same document as ``tfstate``. Both
assertions live in one test on purpose — the trap is the RELATIONSHIP between
the two answers, and pinning either alone lets the other drift.

``terraform`` is not installed on this machine and nothing here requires it.
Degenerate and hostile inputs are built in ``tmp_path`` per the suite
convention; the positive fixtures are the committed corpus.
"""

import json
import os
import sys
from pathlib import Path

import pytest

from gcp_grounding import facts, preflight, provenance
from gcp_grounding.tfsource import discover

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
TF_DIR = FIXTURES / "tf"
HCL_DIR = TF_DIR / "hcl"
STATE_PATH = TF_DIR / "estate.tfstate"
PLAN_PATH = TF_DIR / "estate_plan.json"
SNAPSHOT_PATH = FIXTURES / "snapshot.json"

STATE_DOC = json.loads(STATE_PATH.read_text(encoding="utf-8"))
PLAN_DOC = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
SNAPSHOT_DOC = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))

#: A real ``.terraform/terraform.tfstate`` for a gcs backend: version, serial
#: and lineage exactly like state, a ``backend`` block, and NO ``resources``
#: array — which is what makes it read as a clean empty estate.
BACKEND_STUB = {
    "version": 3,
    "serial": 1,
    "lineage": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
    "backend": {
        "type": "gcs",
        "config": {"bucket": "acme-tfstate", "prefix": "prod"},
        "hash": 1234567890,
    },
}

#: A genuine v3 state file. Note the shape: v3 nests everything under
#: ``modules`` and has no top-level ``resources`` array at all, which is why
#: reading it with a v4 reader yields zero resources rather than an error.
V3_STATE = {
    "version": 3,
    "terraform_version": "0.11.14",
    "serial": 7,
    "lineage": "9a8b7c6d-5e4f-3021-1234-abcdefabcdef",
    "modules": [{"path": ["root"], "outputs": {},
                 "resources": {"google_compute_network.vpc": {}},
                 "depends_on": []}],
}

#: The ``package.json`` shape: a ``name`` and a ``version``, the two keys most
#: likely to be mistaken for a policy name and a state version.
PACKAGE_JSON = {
    "name": "acme-infra",
    "version": "1.0.0",
    "dependencies": {"typescript": "^5.4.0"},
    "scripts": {"build": "tsc"},
}


def _write(path: Path, document) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


# -- the vocabulary and the two translation maps ------------------------------


def test_artifact_kinds_are_the_five_the_readers_dispatch_on():
    assert discover.ARTIFACT_KINDS == ("plan_json", "state_json", "tfstate",
                                       "hcl", "hcl_json")


def test_classification_order_covers_every_kind_exactly_once():
    assert sorted(discover.CLASSIFICATION_ORDER) == sorted(discover.ARTIFACT_KINDS)


def test_the_order_puts_the_plan_arm_last():
    # The structural inversion of the terraform_version trap: preflight checks
    # the plan keys FIRST and that is exactly how it swallows a state file.
    order = discover.CLASSIFICATION_ORDER
    assert order[-1] == "plan_json"
    assert order.index("tfstate") < order.index("plan_json")
    # `terraform show -json` of STATE also carries a format_version, so the
    # state representation has to be recognised before the plan arm too.
    assert order.index("state_json") < order.index("plan_json")


def test_source_for_kind_is_total_over_the_kinds_and_lands_in_one_vocabulary():
    assert set(discover.SOURCE_FOR_KIND) == set(discover.ARTIFACT_KINDS)
    assert set(discover.SOURCE_FOR_KIND.values()) <= set(provenance.SOURCES)
    assert discover.SOURCE_FOR_KIND == {
        "plan_json": "tfplan-prior",
        "state_json": "tfstate",
        "tfstate": "tfstate",
        "hcl": "hcl",
        "hcl_json": "hcl",
    }


def test_proposed_source_for_kind_lands_in_the_proposed_vocabulary():
    assert set(discover.PROPOSED_SOURCE_FOR_KIND.values()) <= set(
        facts.PROPOSED_SOURCES)
    assert discover.PROPOSED_SOURCE_FOR_KIND == {
        "plan_json": "tfplan-planned",
        "hcl": "hcl-proposed",
        "hcl_json": "hcl-proposed",
    }


@pytest.mark.parametrize("kind", ("tfstate", "state_json"))
def test_a_state_file_has_no_proposed_spelling_at_all(kind):
    # Not "maps to empty" — ABSENT. A state file records what exists; there is
    # no spelling under which it could become a proposed change.
    assert kind not in discover.PROPOSED_SOURCE_FOR_KIND


def test_the_two_maps_are_disjoint_vocabularies():
    # facts.PROPOSED_SOURCES is disjoint from provenance.SOURCES by
    # construction; the two maps must not blur that.
    assert not (set(discover.SOURCE_FOR_KIND.values())
                & set(discover.PROPOSED_SOURCE_FOR_KIND.values()))


# -- THE NON-STEALING MATRIX --------------------------------------------------


NON_STEALING = [
    pytest.param(path, id=path.name)
    for path in sorted(POLICIES.glob("*.json"))
] + [pytest.param(SNAPSHOT_PATH, id="snapshot.json")]


def test_the_matrix_covers_all_seven_committed_policy_fixtures():
    assert len(sorted(POLICIES.glob("*.json"))) == 7


@pytest.mark.parametrize("path", NON_STEALING)
def test_a_policy_document_is_never_stolen_as_a_terraform_source(path):
    artifact = discover.classify_path(path)
    assert artifact.rejected, (
        f"{path.name} was classified as {artifact.kind!r}. It is a PROPOSAL — "
        f"the document under review — and a discoverer that takes it as a "
        f"current-state source grounds the change against itself, so every "
        f"widening check that should have caught it passes.")
    assert artifact.reason, "a rejection with no reason is a silent drop"
    assert str(path) in artifact.reason
    assert artifact.kind == "" and artifact.source == ""
    assert artifact.proposed_source == "" and artifact.ref is None


@pytest.mark.parametrize("document,name", [
    (PACKAGE_JSON, "package.json"),
    ({}, "empty.json"),
])
def test_an_unrelated_json_document_is_rejected_with_a_reason(document, name,
                                                              tmp_path):
    artifact = discover.classify_path(_write(tmp_path / name, document))
    assert artifact.rejected and artifact.reason


def test_the_three_plan_shaped_policy_fixtures_are_refused_as_proposals():
    # These three ARE valid terraform plan JSON. They are refused because they
    # carry no `prior_state`: SOURCE_FOR_KIND maps plan_json onto
    # `tfplan-prior`, the REFRESHED read of reality, and a plan without one
    # describes only what someone wants to happen.
    for name in ("tf_plan_good.json", "tf_plan_bad.json", "tf_plan_full.json"):
        artifact = discover.classify_path(POLICIES / name)
        assert artifact.rejected, name
        assert "prior_state" in artifact.reason, name
        assert "document under review" in artifact.reason, name


# -- the committed corpus classifies correctly --------------------------------


@pytest.mark.parametrize("path,kind,source,proposed", [
    (STATE_PATH, "tfstate", "tfstate", ""),
    (PLAN_PATH, "plan_json", "tfplan-prior", "tfplan-planned"),
    (HCL_DIR / "main.tf", "hcl", "hcl", "hcl-proposed"),
    (HCL_DIR / "unresolvable.tf", "hcl", "hcl", "hcl-proposed"),
    (HCL_DIR / "perimeter.tf.json", "hcl_json", "hcl", "hcl-proposed"),
    (HCL_DIR / "proposal.tf.json", "hcl_json", "hcl", "hcl-proposed"),
], ids=lambda v: getattr(v, "name", v) or "-")
def test_a_committed_fixture_classifies_to_its_kind(path, kind, source,
                                                    proposed):
    artifact = discover.classify_path(path)
    assert artifact.accepted, artifact.reason
    assert artifact.kind == kind
    assert artifact.source == source
    assert artifact.proposed_source == proposed
    assert artifact.reason == ""


def test_an_accepted_artifact_carries_a_provenance_ref():
    artifact = discover.classify_path(STATE_PATH)
    assert isinstance(artifact.ref, provenance.ArtifactRef)
    assert artifact.ref.path == str(STATE_PATH)
    assert artifact.ref.kind == "tfstate"
    assert artifact.ref.source == "tfstate"
    assert len(artifact.ref.sha256) == 64
    assert artifact.ref.size == STATE_PATH.stat().st_size
    assert artifact.ref.mtime == pytest.approx(STATE_PATH.stat().st_mtime)


# -- THE terraform_version TRAP, pinned side by side --------------------------


def test_the_committed_tfstate_classifies_as_state_here_and_as_a_plan_there():
    here = discover.classify_path(STATE_PATH)
    assert here.kind == "tfstate"
    # THE TRAP, stated as an assertion rather than a comment: detect_kind
    # returns the PLAN kind for the very same document, because its plan-key
    # set contains `terraform_version` and every tfstate carries one.
    assert "terraform_version" in STATE_DOC
    assert "terraform_version" in preflight._TF_PLAN_KEYS
    assert preflight.detect_kind(STATE_DOC) == "tf_plan"
    # And the trap is not merely academic: a plan-shaped read of this document
    # finds none of the plan's own keys, so it degrades to zero claims.
    assert "planned_values" not in STATE_DOC
    assert "resource_changes" not in STATE_DOC
    assert "format_version" not in STATE_DOC


def test_the_detector_can_never_decide_a_positive_classification(monkeypatch):
    # Make detect_kind claim EVERYTHING is a terraform plan. Nothing about the
    # classification may move: the detector's opinion can only lengthen a
    # rejection message.
    monkeypatch.setattr(preflight, "detect_kind", lambda doc: "tf_plan")
    assert discover.classify_path(STATE_PATH).kind == "tfstate"
    assert discover.classify_path(PLAN_PATH).kind == "plan_json"
    assert discover.classify_path(SNAPSHOT_PATH).rejected
    assert discover.classify_path(POLICIES / "iam_policy_good.json").rejected


def test_the_detector_opinion_appears_in_a_rejection_reason():
    artifact = discover.classify_path(POLICIES / "iam_policy_good.json")
    assert artifact.rejected
    assert "iam_policy" in artifact.reason
    assert "PROPOSAL" in artifact.reason


# -- the shared v4 sniff ------------------------------------------------------


def test_is_v4_state_is_true_for_the_committed_tfstate():
    assert discover.is_v4_state(STATE_DOC) is True


@pytest.mark.parametrize("doc,name", [
    (PLAN_DOC, "the plan fixture"),
    (SNAPSHOT_DOC, "the vocabulary snapshot"),
    (V3_STATE, "a v3 state file"),
    (BACKEND_STUB, "a remote-backend stub"),
    ({"version": 4, "resources": []}, "a v4 envelope with no lineage"),
    ({"version": 4, "lineage": "x"}, "a v4 envelope with no resources"),
    ({"version": "4", "lineage": "x", "resources": []}, "a stringly version"),
    ({"bindings": [], "etag": "e", "version": 3}, "an IAM allow policy"),
    (None, "None"),
    ([], "a list"),
], ids=lambda v: v if isinstance(v, str) else "")
def test_is_v4_state_is_false_for_everything_else(doc, name):
    assert discover.is_v4_state(doc) is False, name


def test_the_tfstate_arm_runs_the_shared_sniff_and_not_a_parallel_one(monkeypatch):
    # Not "behaves the same" — literally the same function. Neutering it must
    # neuter the arm, which is what makes three drifting copies impossible.
    monkeypatch.setattr(discover, "is_v4_state", lambda doc: False)
    artifact = discover.classify_path(STATE_PATH)
    assert artifact.rejected


def test_state_not_a_proposal_is_one_template_parameterised_by_path():
    assert "{path}" in discover.STATE_NOT_A_PROPOSAL
    rendered = discover.STATE_NOT_A_PROPOSAL.format(path="/tmp/estate.tfstate")
    assert rendered.startswith("/tmp/estate.tfstate:")
    assert "Terraform state" in rendered
    assert "not a proposed change" in rendered
    assert "CURRENT-state source" in rendered
    assert "terraform-state flag" in rendered
    assert "config file" in rendered
    assert "{path}" not in rendered


# -- a v3 state is refused LOUDLY, never read as empty ------------------------


def test_a_v3_tfstate_is_rejected_rather_than_read_as_an_empty_estate(tmp_path):
    artifact = discover.classify_path(
        _write(tmp_path / "legacy.tfstate", V3_STATE))
    assert artifact.rejected
    assert "version 3" in artifact.reason
    # The rejection has to SAY why silence would be worse, because "no
    # resources" and "a clean empty estate" are the same bytes to a caller.
    assert "empty estate" in artifact.reason
    assert "REFUSED" in artifact.reason


def test_a_v3_tfstate_is_not_mistaken_for_a_backend_stub(tmp_path):
    # A real v3 has no top-level `resources` array either — it nests them under
    # `modules` — so the stub arm must not swallow it and send the user off to
    # run a state pull against a backend that is not there.
    path = _write(tmp_path / "legacy.tfstate", V3_STATE)
    artifact = discover.classify_path(path)
    assert artifact.reason != discover.REMOTE_BACKEND_STUB.format(path=str(path))
    assert "remote-backend" not in artifact.reason
    assert "never fetches anything" not in artifact.reason


# -- THE REMOTE-BACKEND STUB --------------------------------------------------


def test_a_backend_stub_yields_the_remote_backend_message(tmp_path):
    path = _write(tmp_path / "terraform.tfstate", BACKEND_STUB)
    artifact = discover.classify_path(path)
    assert artifact.rejected
    assert artifact.reason == discover.REMOTE_BACKEND_STUB.format(path=str(path))
    assert "NOTHING was captured" in artifact.reason
    assert "state pull" in artifact.reason
    assert "never fetches anything" in artifact.reason


def test_a_v4_envelope_with_no_resources_array_is_the_same_stub(tmp_path):
    path = _write(tmp_path / "terraform.tfstate",
                  {"version": 4, "lineage": "x", "serial": 2})
    artifact = discover.classify_path(path)
    assert artifact.reason == discover.REMOTE_BACKEND_STUB.format(path=str(path))


def test_an_iam_policy_is_not_dragged_into_the_state_arm_by_its_version():
    # An IAM allow policy carries `version: 3`. If the state arm triggered on a
    # bare version key it would refuse it as a stale state file, which is a
    # true rejection with a completely misleading reason.
    artifact = discover.classify_path(POLICIES / "iam_policy_good.json")
    assert "version 3" not in artifact.reason
    assert "state pull" not in artifact.reason


# -- the plan and state-representation arms -----------------------------------


def test_a_plan_with_prior_state_is_the_current_state_side(tmp_path):
    path = _write(tmp_path / "plan.json", {
        "format_version": "1.2",
        "terraform_version": "1.9.5",
        "prior_state": {"values": {"root_module": {"resources": []}}},
        "resource_changes": [],
    })
    artifact = discover.classify_path(path)
    assert artifact.kind == "plan_json"
    assert artifact.source == "tfplan-prior"


@pytest.mark.parametrize("format_version", ("2.0", "0.1", "99.1"))
def test_an_unknown_plan_format_major_is_refused_loudly(format_version, tmp_path):
    path = _write(tmp_path / "plan.json", {
        "format_version": format_version,
        "terraform_version": "9.9.9",
        "prior_state": {"values": {"root_module": {"resources": []}}},
        "resource_changes": [],
    })
    artifact = discover.classify_path(path)
    assert artifact.rejected
    assert format_version in artifact.reason
    assert "major version 1" in artifact.reason


def test_the_plan_minor_version_is_not_pinned(tmp_path):
    for minor in ("1.0", "1.2", "1.87"):
        path = _write(tmp_path / f"plan-{minor}.json", {
            "format_version": minor,
            "prior_state": {"values": {"root_module": {"resources": []}}},
            "resource_changes": [],
        })
        assert discover.classify_path(path).kind == "plan_json", minor


def test_terraform_show_json_state_is_state_json_not_a_plan(tmp_path):
    # `terraform show -json <statefile>` carries a format_version too. A
    # plan-first order would refuse it for lacking a prior_state it was never
    # going to have.
    path = _write(tmp_path / "shown.json", {
        "format_version": "1.0",
        "terraform_version": "1.9.5",
        "values": {"root_module": {"resources": [
            {"address": "google_compute_network.vpc", "mode": "managed",
             "type": "google_compute_network", "name": "vpc",
             "provider_name": "registry.terraform.io/hashicorp/google",
             "values": {"name": "vpc-main"}}]}},
    })
    artifact = discover.classify_path(path)
    assert artifact.kind == "state_json"
    assert artifact.source == "tfstate"
    assert artifact.proposed_source == ""


def test_a_state_representation_with_resource_changes_is_not_state_json(tmp_path):
    path = _write(tmp_path / "both.json", {
        "format_version": "1.0",
        "values": {"root_module": {"resources": []}},
        "resource_changes": [],
    })
    # It falls through to the plan arm, which refuses it for having no prior
    # state — never silently accepted as a current-state read.
    artifact = discover.classify_path(path)
    assert artifact.rejected
    assert "prior_state" in artifact.reason


# -- the HCL exception, and its limit -----------------------------------------


def test_a_tf_file_is_hcl_by_extension_even_when_it_is_gibberish(tmp_path):
    path = tmp_path / "weird.tf"
    path.write_text("this is not valid HCL at all {{{", encoding="utf-8")
    artifact = discover.classify_path(path)
    assert artifact.kind == "hcl", (
        "raw HCL has no sniffable header, so extension is the ONLY signal; "
        "the reader, not the discoverer, decides what parses")


def test_a_tf_json_still_has_to_carry_a_terraform_block_key(tmp_path):
    path = _write(tmp_path / "impostor.tf.json", {"hello": "world"})
    artifact = discover.classify_path(path)
    assert artifact.rejected
    for key in discover.HCL_BLOCK_KEYS:
        assert key in artifact.reason


@pytest.mark.parametrize("key", discover.HCL_BLOCK_KEYS)
def test_every_terraform_block_key_admits_a_tf_json(key, tmp_path):
    path = _write(tmp_path / f"{key}.tf.json", {key: {}})
    assert discover.classify_path(path).kind == "hcl_json"


def test_a_malformed_tf_json_is_rejected_and_never_handed_to_the_hcl_arm(tmp_path):
    path = tmp_path / "broken.tf.json"
    path.write_text("{not json", encoding="utf-8")
    artifact = discover.classify_path(path)
    assert artifact.rejected
    assert ".tf.json must be JSON" in artifact.reason


def test_a_json_document_that_is_not_an_object_is_rejected(tmp_path):
    path = _write(tmp_path / "array.json", [1, 2, 3])
    artifact = discover.classify_path(path)
    assert artifact.rejected
    assert "JSON object" in artifact.reason


# -- classify_path NEVER raises -----------------------------------------------


def test_a_missing_file_is_a_rejection_record_not_an_oserror(tmp_path):
    artifact = discover.classify_path(tmp_path / "nope.tfstate")
    assert artifact.rejected
    assert "could not be read" in artifact.reason


def test_an_unreadable_file_is_a_rejection_record(tmp_path):
    path = _write(tmp_path / "locked.tfstate", STATE_DOC)
    os.chmod(path, 0o000)
    try:
        artifact = discover.classify_path(path)
    finally:
        os.chmod(path, 0o644)
    if os.geteuid() == 0:                       # root reads anything
        assert artifact.accepted
    else:
        assert artifact.rejected
        assert "could not be read" in artifact.reason


def test_an_oversize_file_is_refused_without_being_read():
    artifact = discover.classify_path(STATE_PATH, max_bytes=16)
    assert artifact.rejected
    assert "over the 16-byte artifact limit" in artifact.reason


def test_undecodable_bytes_are_a_rejection_record(tmp_path):
    path = tmp_path / "binary.tfstate"
    path.write_bytes(b"\xff\xfe\x00\x01\x02\x03")
    artifact = discover.classify_path(path)
    assert artifact.rejected
    assert "not UTF-8" in artifact.reason


def test_pathological_nesting_is_a_rejection_record_not_a_recursionerror(tmp_path):
    depth = sys.getrecursionlimit() * 4
    path = tmp_path / "deep.json"
    path.write_text('{"a":' * depth + "1" + "}" * depth, encoding="utf-8")
    artifact = discover.classify_path(path)
    assert artifact.rejected, "a crash inside a gate is a gate that decided nothing"
    assert artifact.reason


# -- the state backup ---------------------------------------------------------


def test_a_state_backup_is_refused_unless_it_is_opted_into(tmp_path):
    path = _write(tmp_path / "terraform.tfstate.backup", STATE_DOC)
    refused = discover.classify_path(path)
    assert refused.rejected
    assert "BACKUP" in refused.reason
    assert "yesterday's world" in refused.reason
    opted_in = discover.classify_path(path, include_backups=True)
    assert opted_in.kind == "tfstate"


# -- the walk: pruning, symlinks, determinism ---------------------------------


def test_prune_dirs_is_the_enumerated_list():
    assert discover.PRUNE_DIRS == (".git", ".terraform", "node_modules",
                                   "__pycache__", ".venv", ".pytest_cache")


def _tree_with_traps(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "infra").mkdir(parents=True)
    (root / "infra" / "main.tf").write_text(
        'resource "google_compute_network" "vpc" {\n  name = "vpc-main"\n}\n',
        encoding="utf-8")
    # Each trap holds a PERFECTLY VALID v4 state, so a leak is an ACCEPT and
    # not merely a rejection record: the pruning is what has to work.
    _write(root / ".git" / "stashed.tfstate", STATE_DOC)
    _write(root / ".terraform" / "terraform.tfstate", STATE_DOC)
    _write(root / "node_modules" / "pkg" / "terraform.tfstate", STATE_DOC)
    _write(root / "__pycache__" / "cached.tfstate", STATE_DOC)
    _write(root / ".venv" / "share" / "sample.tfstate", STATE_DOC)
    _write(root / ".pytest_cache" / "v" / "old.tfstate", STATE_DOC)
    return root


@pytest.mark.parametrize("pruned", discover.PRUNE_DIRS)
def test_a_pruned_directory_yields_zero_artifacts(pruned, tmp_path):
    root = _tree_with_traps(tmp_path)
    found = discover.discover(root)
    leaked = [a.path for a in found.artifacts
              if f"{os.sep}{pruned}{os.sep}" in a.path]
    assert not leaked, f"{pruned}/ leaked {leaked}"
    # And nothing under it was even opened, so it produces no rejection either.
    assert not [a.path for a in found.rejected
                if f"{os.sep}{pruned}{os.sep}" in a.path]


def test_the_pruning_test_tree_is_not_vacuously_empty(tmp_path):
    root = _tree_with_traps(tmp_path)
    found = discover.discover(root)
    assert [Path(a.path).name for a in found.artifacts] == ["main.tf"]
    assert found.artifacts[0].kind == "hcl"


def test_a_pruned_directory_is_named_in_the_notes(tmp_path):
    root = _tree_with_traps(tmp_path)
    found = discover.discover(root)
    for pruned in discover.PRUNE_DIRS:
        assert any(pruned in note and "pruned" in note for note in found.notes), (
            f"{pruned}/ was skipped silently; a walk that says nothing about "
            f"what it refused to enter reads as a walk that found nothing")


def test_a_symlink_out_of_the_tree_is_not_followed_by_default(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    link = root / "borrowed.tfstate"
    try:
        link.symlink_to(STATE_PATH)
    except (OSError, NotImplementedError):      # pragma: no cover
        pytest.skip("this platform cannot create symbolic links")
    assert discover.discover(root).artifacts == ()
    assert any("not followed" in note for note in discover.discover(root).notes)


def test_a_symlink_is_followed_only_through_the_named_opt_in(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    link = root / "borrowed.tfstate"
    try:
        link.symlink_to(STATE_PATH)
    except (OSError, NotImplementedError):      # pragma: no cover
        pytest.skip("this platform cannot create symbolic links")
    found = discover.discover(root, follow_symlinks=True)
    assert [a.kind for a in found.artifacts] == ["tfstate"]
    assert found.artifacts[0].path == str(link)


def test_a_symlinked_directory_is_not_descended_by_default(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    try:
        (root / "vendored").symlink_to(TF_DIR, target_is_directory=True)
    except (OSError, NotImplementedError):      # pragma: no cover
        pytest.skip("this platform cannot create symbolic links")
    assert discover.discover(root).artifacts == ()
    assert discover.discover(root, follow_symlinks=True).artifacts


def test_the_committed_tf_tree_walks_to_the_whole_corpus():
    found = discover.discover(TF_DIR)
    assert {(Path(a.path).name, a.kind) for a in found.artifacts} == {
        ("estate.tfstate", "tfstate"),
        ("estate_plan.json", "plan_json"),
        ("main.tf", "hcl"),
        ("unresolvable.tf", "hcl"),
        ("perimeter.tf.json", "hcl_json"),
        ("proposal.tf.json", "hcl_json"),
    }
    assert found.rejected == ()


def test_two_runs_produce_identical_sha256_and_ordering():
    first = discover.discover(TF_DIR)
    second = discover.discover(TF_DIR)
    assert first.paths == second.paths
    assert first.paths == tuple(sorted(first.paths)), "the order is not sorted"
    assert ([a.ref.sha256 for a in first.artifacts]
            == [a.ref.sha256 for a in second.artifacts])
    assert ([a.ref.mtime for a in first.artifacts]
            == [a.ref.mtime for a in second.artifacts])
    assert first.artifacts == second.artifacts


def test_discover_over_a_single_file_classifies_just_that_file():
    found = discover.discover(STATE_PATH)
    assert [a.kind for a in found.artifacts] == ["tfstate"]


def test_the_walk_records_a_refused_candidate_rather_than_dropping_it(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _write(root / "iam.json", json.loads(
        (POLICIES / "iam_policy_good.json").read_text(encoding="utf-8")))
    _write(root / "terraform.tfstate.backup", STATE_DOC)
    found = discover.discover(root)
    assert found.artifacts == ()
    assert {Path(a.path).name for a in found.rejected} == {
        "iam.json", "terraform.tfstate.backup"}
    assert all(a.reason for a in found.rejected)


def test_by_kind_selects_the_readers_dispatch_group():
    found = discover.discover(TF_DIR)
    assert [Path(a.path).name for a in found.by_kind("hcl_json")] == [
        "perimeter.tf.json", "proposal.tf.json"]
    assert found.by_kind("state_json") == ()


# -- the Artifact record refuses to be half-built -----------------------------


def test_an_artifact_is_either_classified_or_refused_never_both():
    with pytest.raises(ValueError, match="one or the other"):
        discover.Artifact(path="x.tfstate", kind="tfstate", reason="also bad")


def test_an_artifact_with_neither_a_kind_nor_a_reason_is_refused():
    with pytest.raises(ValueError, match="neither classified nor rejected"):
        discover.Artifact(path="x.tfstate")


def test_an_artifact_kind_must_be_one_of_the_five():
    with pytest.raises(ValueError, match="is not one of"):
        discover.Artifact(path="x.tfstate", kind="tf_plan")
