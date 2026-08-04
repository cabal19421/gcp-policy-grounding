"""Tests for :mod:`gcp_grounding.hierarchy` — the Datalog ancestor closure over
the resource hierarchy.

The module answers pure structural ancestry questions (who is above whom) for
hierarchical-firewall evaluation. It carries the snapshot's UNKNOWN-vs-absent
honesty contract: an uncaptured hierarchy yields UNKNOWN from every accessor and
None from ``hierarchy_program``, while a node merely missing from a *captured*
hierarchy is a fact — an empty ancestry, never UNKNOWN. It must also accept the
``projects/<number>`` alias, order ancestors OUTERMOST FIRST, and survive a
cyclic hierarchy without hanging.
"""

import logging
import logging.handlers
from pathlib import Path

from gcp_grounding import hierarchy
from gcp_grounding.core.datalog import Datalog
from gcp_grounding.hierarchy import (
    ancestors, ancestry_chain, descendants, hierarchy_program,
)
from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
ESTATE = FIXTURES / "estate_snapshot.json"
PARTIAL = FIXTURES / "estate_partial_snapshot.json"

ORG = "organizations/1"
FOLDER = "folders/2"
PROJECT = "projects/acme-prod"
PROJECT_ALIAS = "projects/123456"  # the CRM project keyed by its number


def _estate() -> GcpSnapshot:
    return GcpSnapshot.load(ESTATE)


def _capture(fn):
    """Run *fn* with a handler bolted straight onto the hierarchy logger, so
    capture does not depend on propagation config. Returns (result, records)."""
    handler = logging.handlers.BufferingHandler(capacity=10_000)
    logger = hierarchy.logger
    prior = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        result = fn()
    finally:
        logger.removeHandler(handler)
        logger.setLevel(prior)
    return result, handler.buffer


# -- the ancestry ordering contract, against the real estate fixture ----------


def test_ancestors_outermost_first():
    # OUTERMOST FIRST: organization at index 0, immediate parent last.
    assert ancestors(_estate(), PROJECT) == (ORG, FOLDER)


def test_ancestors_number_alias_is_identical():
    snap = _estate()
    assert ancestors(snap, PROJECT_ALIAS) == ancestors(snap, PROJECT) == (ORG, FOLDER)


def test_ancestors_of_org_is_empty():
    # The org is the root: a captured node with no recorded parent → empty tuple.
    result = ancestors(_estate(), ORG)
    assert result == ()
    assert result is not UNKNOWN


def test_ancestry_chain_appends_the_node_itself():
    assert ancestry_chain(_estate(), PROJECT) == (ORG, FOLDER, PROJECT)


def test_ancestry_chain_alias_resolves_to_canonical_leaf():
    # The number alias resolves to the canonical key throughout the chain.
    assert ancestry_chain(_estate(), PROJECT_ALIAS) == (ORG, FOLDER, PROJECT)


def test_descendants_contains_folder_and_project():
    result = descendants(_estate(), ORG)
    assert result is not UNKNOWN
    assert FOLDER in result
    assert PROJECT in result
    assert result == frozenset({FOLDER, PROJECT})


def test_descendants_of_leaf_is_empty():
    assert descendants(_estate(), PROJECT) == frozenset()


def test_descendants_number_alias_is_identical():
    snap = _estate()
    assert descendants(snap, PROJECT_ALIAS) == descendants(snap, PROJECT)


# -- the Datalog program itself -----------------------------------------------


def test_hierarchy_program_facts_and_closure():
    dl = hierarchy_program(_estate())
    assert isinstance(dl, Datalog)
    # Base facts: node / node_type / parent (only for non-null parents).
    assert dl.holds("node", PROJECT)
    assert dl.holds("node_type", PROJECT, "project")
    assert dl.holds("node_type", ORG, "organization")
    assert dl.holds("parent", PROJECT, FOLDER)
    assert dl.holds("parent", FOLDER, ORG)
    assert not dl.holds("parent", ORG, None)  # the root has no parent fact
    # The recursive closure reaches the transitive ancestor.
    dl.run()
    assert dl.holds("ancestor", PROJECT, FOLDER)
    assert dl.holds("ancestor", PROJECT, ORG)


# -- honesty: an uncaptured hierarchy abstains everywhere ----------------------


def test_partial_snapshot_program_is_none():
    assert hierarchy_program(GcpSnapshot.load(PARTIAL)) is None


def test_partial_snapshot_every_accessor_is_unknown():
    snap = GcpSnapshot.load(PARTIAL)
    assert snap.resource_hierarchy is None  # precondition for the contract
    assert ancestors(snap, PROJECT) is UNKNOWN
    assert ancestry_chain(snap, PROJECT) is UNKNOWN
    assert descendants(snap, ORG) is UNKNOWN


# -- absent-in-a-captured-hierarchy is a FACT, not UNKNOWN ---------------------


def test_absent_node_in_captured_hierarchy_is_empty_not_unknown():
    snap = _estate()
    result = ancestors(snap, "projects/does-not-exist")
    assert result == ()
    assert result is not UNKNOWN
    assert descendants(snap, "projects/does-not-exist") == frozenset()
    assert ancestry_chain(snap, "projects/does-not-exist") == ("projects/does-not-exist",)


# -- a parent edge pointing outside the captured table is retained -------------


def test_parent_outside_table_is_retained_and_ends_chain():
    # Capture scoped below the org root: folders/2 records org/1 as parent, but
    # org/1 itself is not in the table. The edge is kept; the chain ends there.
    snap = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T00:00:00Z",
        "resource_hierarchy": {
            FOLDER: {"parent": ORG, "type": "folder"},
        },
    })
    result, records = _capture(lambda: ancestors(snap, FOLDER))
    assert result == (ORG,)  # the out-of-table parent is retained
    assert any(r.levelno == logging.DEBUG for r in records)


# -- a cyclic hierarchy must terminate and log --------------------------------


def test_cycle_terminates_and_logs_warning():
    snap = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T00:00:00Z",
        "resource_hierarchy": {
            "folders/a": {"parent": "folders/b", "type": "folder"},
            "folders/b": {"parent": "folders/a", "type": "folder"},
        },
    })
    result, records = _capture(lambda: ancestors(snap, "folders/a"))
    # Terminates, returning the prefix walked before the cycle closed.
    assert result == ("folders/b",)
    assert any(r.levelno == logging.WARNING and "cycle" in r.getMessage().lower()
               for r in records)


def test_cycle_closure_and_descendants_terminate():
    snap = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T00:00:00Z",
        "resource_hierarchy": {
            "folders/a": {"parent": "folders/b", "type": "folder"},
            "folders/b": {"parent": "folders/a", "type": "folder"},
        },
    })
    # The naive fixpoint terminates on the cyclic graph (finite closure).
    assert descendants(snap, "folders/a") == frozenset({"folders/a", "folders/b"})


# -- a three-level chain orders correctly -------------------------------------


def test_three_level_chain_orders_outermost_first():
    snap = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T00:00:00Z",
        "resource_hierarchy": {
            "organizations/1": {"parent": None, "type": "organization"},
            "folders/2": {"parent": "organizations/1", "type": "folder"},
            "folders/3": {"parent": "folders/2", "type": "folder"},
            "projects/deep": {"parent": "folders/3", "type": "project"},
        },
    })
    assert ancestors(snap, "projects/deep") == (
        "organizations/1", "folders/2", "folders/3")
    assert ancestry_chain(snap, "projects/deep") == (
        "organizations/1", "folders/2", "folders/3", "projects/deep")
