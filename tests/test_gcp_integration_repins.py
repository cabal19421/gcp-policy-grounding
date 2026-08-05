"""The self-test of the integrator re-pin register.

A record nobody checks is a comment. `tests/integration_repins.py` claims, for
each expectation an integrator changed, that a specific text stands in a specific
module today and that a specific branch-authored text either is landed under a
strict xfail or is genuinely superseded. Every one of those claims is checked
here, against the tree, on every run:

* the ``integrated`` text must occur VERBATIM in the named module (whitespace-
  normalized, the same comparison the spec register uses), so an entry cannot
  describe a tree that has moved on;
* an entry naming an ``escalation_id`` must have that id in
  `tests.escalations.ESCALATIONS`, must have its ``branch_text`` PRESENT in the
  module, and that module must carry the strict xfail the escalation register
  demands — checked with the frozen self-test's own AST checker, not a second
  copy of it;
* an entry with no ``escalation_id`` must have ``branch_text`` ABSENT and must
  say what superseded it. "Superseded" and "parked" are the only two states; a
  third would be "quietly changed";
* every node id must be collectible, so a re-pin cannot outlive its test.

And the frozen-path register is checked by RECOMPUTING the blob hash of each
recorded path. That is what stops the record going stale in the one direction
that matters: another edit to a frozen acceptance path reddens this suite until
it is either recorded or reverted.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tests.escalations import ESCALATIONS
from tests.integration_repins import FROZEN_PATH_EDITS, REPINS
from tests.test_gcp_escalations import strict_xfail_failure
from tests.test_gcp_spec_assertions import (
    REPO_ROOT,
    module_source,
    node_is_collectible,
    normalize,
)

_ESCALATION_BY_ID = {escalation.id: escalation for escalation in ESCALATIONS}

_IDS = [repin.id for repin in REPINS]


def blob_sha1(data: bytes) -> str:
    """git's object name for these bytes, computed here so the frozen-path check
    needs no git binary and works in a clean container."""
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


def test_the_hasher_is_gits_hasher():
    """Must-fail-first for the check below: a hasher that agreed with nothing
    would make every frozen-path assertion vacuously true."""
    assert blob_sha1(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    assert blob_sha1(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


@pytest.mark.parametrize("repin", REPINS, ids=_IDS)
def test_every_repin_has_the_shape_the_register_promises(repin):
    assert repin.id.startswith("RP-"), repin
    assert repin.branch.startswith("agent/"), repin
    assert "::" in repin.node_id, repin
    assert repin.node_id.split("::")[0].endswith(".py"), repin
    assert repin.branch_text.strip(), f"{repin.id}: no branch text recorded"
    assert repin.integrated.strip(), f"{repin.id}: no integrated text recorded"
    assert normalize(repin.branch_text) != normalize(repin.integrated), (
        f"{repin.id}: the two texts are the same — a re-pin that changed nothing "
        "is not a re-pin, and an entry for it hides the ones that are real")
    assert len(repin.measurement.split()) >= 20, (
        f"{repin.id}: a measurement this short is an assertion of good faith, "
        "not a measurement")
    assert repin.kept.strip(), (
        f"{repin.id}: nothing is recorded as KEPT. An integrator who changes an "
        "expectation and adds nothing has deleted coverage.")


def test_ids_are_unique():
    duplicated = sorted({name for name in _IDS if _IDS.count(name) > 1})
    assert not duplicated, f"duplicate re-pin ids: {duplicated}"


@pytest.mark.parametrize("repin", REPINS, ids=_IDS)
def test_every_repin_node_is_collectible(repin):
    assert node_is_collectible(repin.node_id), (
        f"{repin.id}: {repin.node_id} does not resolve to a test — a re-pin "
        "cannot outlive the test it re-pinned")


@pytest.mark.parametrize("repin", REPINS, ids=_IDS)
def test_the_integrated_text_is_really_in_the_tree(repin):
    """PRESENCE, not narration: the text this register says stands must stand."""
    module = repin.node_id.split("::")[0]
    source = module_source(module)
    assert source is not None, f"{repin.id}: {module} is not in this checkout"
    assert normalize(repin.integrated) in normalize(source), (
        f"{repin.id}: the text this register says the tree carries is NOT in "
        f"{module}:\n  {repin.integrated}\n"
        "  Either the tree moved on and this entry is stale, or the entry was "
        "wrong when it was written. Both are worth a red suite.")


@pytest.mark.parametrize("repin", REPINS, ids=_IDS)
def test_a_parked_expectation_is_landed_and_a_superseded_one_is_explained(repin):
    """The two legal states, and nothing between them."""
    module = repin.node_id.split("::")[0]
    source = module_source(module)
    assert source is not None, f"{repin.id}: {module} is not in this checkout"
    present = normalize(repin.branch_text) in normalize(source)
    if repin.escalation_id:
        escalation = _ESCALATION_BY_ID.get(repin.escalation_id)
        assert escalation is not None, (
            f"{repin.id}: names escalation {repin.escalation_id}, which is not in "
            "tests/escalations.py — this is the exact failure this register was "
            "created to answer: a commit message that CLAIMED an escalation "
            "nobody had written.")
        assert present, (
            f"{repin.id}: {repin.escalation_id} parks this expectation, so its "
            f"text must be LANDED in {module}, not described:\n  "
            f"{repin.branch_text}")
        failure = strict_xfail_failure(escalation, module_source(
            escalation.node_id.split("::")[0]) or "")
        assert failure is None, failure
    else:
        assert repin.superseded_by.strip(), (
            f"{repin.id}: no escalation and no superseded_by. An expectation that "
            "is neither parked nor superseded was just changed.")
        assert not present, (
            f"{repin.id}: recorded as SUPERSEDED, but its text is still in "
            f"{module}. If both texts hold this is a union and needs no entry; if "
            "it is parked it needs an escalation id.")


@pytest.mark.parametrize("edit", FROZEN_PATH_EDITS, ids=[e.path for e in FROZEN_PATH_EDITS])
def test_every_recorded_frozen_path_still_hashes_to_its_recorded_blob(edit):
    """THE TOOTH. Recomputed every run, so a frozen acceptance path cannot drift
    one further byte without this record being updated or the edit reverted."""
    path = Path(REPO_ROOT) / edit.path
    assert path.is_file(), f"{edit.path} is recorded as edited but is not here"
    got = blob_sha1(path.read_bytes())
    assert got == edit.head_blob, (
        f"{edit.path} is a FROZEN acceptance path and its content is no longer "
        f"the content this register records: {got} != {edit.head_blob}.\n"
        "  Either revert the edit, or record it here with its measurement and "
        "what would close it. A frozen path that drifts unrecorded is the "
        "weakening this register exists to make impossible to do quietly.\n"
        f"  what is already recorded: {edit.what_changed}")
    assert edit.branch_blob != edit.head_blob, (
        f"{edit.path}: branch_blob == head_blob, so there is nothing to record — "
        "the entry should be retired, not left standing as a permanent alarm.")


# -- the residual risk the frozen register advertises a closer for -------------
#
# tests/spec_assertions.py names the in-repo MUTATION CONTRACT as what closes its
# second residual risk: "a module still listed in PENDING_MODULES can later be
# DELETED without this check firing, because a missing module is exactly the
# pending shape." That contract exists on no branch in this repository —
# tests/mutation_contract.py, tests/mutation_entries.py,
# test_gcp_mutation_machinery.py and test_gcp_mutation_contract.py are nowhere —
# so the frozen register currently advertises a safety net the tree does not have.
#
# The half of it that can be closed from OUTSIDE a frozen path is closed here.
# Every module PENDING_MODULES lists is PRESENT in the integrated tree, so the
# pending shape no longer excuses any of them: delete one and this reddens, which
# is precisely the deletion the register cannot catch by itself. This is not the
# contract (which pins BEHAVIOUR per family); it is the deletion guard, and it
# needs no edit to a frozen file to hold.


def test_no_module_the_frozen_register_pins_can_be_deleted_quietly():
    from tests.spec_assertions import ASSERTIONS, PENDING_MODULES

    missing = sorted(module for module in PENDING_MODULES
                     if not (Path(REPO_ROOT) / module).is_file())
    assert not missing, (
        f"modules the spec register pins are gone from the checkout: {missing}.\n"
        "  Every one of them is present in the integrated tree, so a missing one "
        "is a DELETION, not the pending shape — and the frozen register cannot "
        "tell those apart, which is the residual risk its docstring names.\n"
        "  If a module was deliberately retired, retire its register entries with "
        "it (that is its owner's edit, on its owner's branch), rather than "
        "letting a frozen check go quiet.")
    # Non-vacuity: PENDING_MODULES is not empty, and every module any entry names
    # is here too — so this test cannot pass by having nothing to check.
    assert PENDING_MODULES, "PENDING_MODULES is empty; this test checks nothing"
    for entry in ASSERTIONS:
        assert (Path(REPO_ROOT) / entry.module).is_file(), entry


@pytest.mark.parametrize("edit", FROZEN_PATH_EDITS, ids=[e.path for e in FROZEN_PATH_EDITS])
def test_every_frozen_path_edit_says_why_it_is_open_and_what_closes_it(edit):
    assert len(edit.why_open.split()) >= 30, (
        f"{edit.path}: an edit to a frozen acceptance path needs the reasoning "
        "in full, including why the two ordinary resolutions were not takeable")
    assert len(edit.what_closes.split()) >= 10, (
        f"{edit.path}: an open divergence with no stated remedy is a permanent "
        "exception, which is what freezing the path was meant to prevent")
    assert len(edit.branch_blob) == 40 and len(edit.head_blob) == 40, edit
    assert len(edit.commit) == 40, f"{edit.path}: name the commit in full"
