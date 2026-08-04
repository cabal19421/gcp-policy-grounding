"""Datalog ancestor closure over the GCP resource hierarchy.

Hierarchical-firewall evaluation needs to know a project's org/folder ancestry:
policies attach at the organization, at folders, and at the project, and they
are consulted OUTERMOST FIRST — the organization's rules win before a folder's,
a folder's before the project's. This module answers those ancestry questions
by running the vendored, recursion-capable Datalog engine
(:mod:`gcp_grounding.core.datalog`) over the ``resource_hierarchy`` snapshot
table. It asks pure structural questions — who is above whom — so there is no
z3 here and no verdict; the four honest buckets belong to the checks that
consume this, not to the closure itself.

The one honesty semantic mirrors the rest of the snapshot API — **unknown vs
absent**:

- ``resource_hierarchy is None`` (the category was never captured) makes every
  accessor return the :data:`~gcp_grounding.knowledge.UNKNOWN` singleton, so a
  caller abstains (``unverified``) rather than guessing an ancestry. Callers
  MUST compare ``is UNKNOWN`` and never truth-test the result.
- A node absent from a *captured* hierarchy is a fact, not an unknown: the
  hierarchy was enumerated, so "this node has no recorded parent" resolves to an
  EMPTY tuple / EMPTY frozenset, never UNKNOWN.

Two robustness details the real world forces:

- The ``projects/<number>`` alias (VPC-SC keys a project by number, CRM by id)
  is accepted by resolving through :meth:`GcpSnapshot.hierarchy_node` first and
  walking from the record's canonical key.
- A cycle in the recorded parent edges must neither hang nor crash. The Datalog
  fixpoint terminates naturally, and :func:`ancestors` walks the parent links
  itself with a visited set so the ORDER is deterministic; on meeting a node it
  has already seen it logs a warning and returns the prefix walked so far.
"""

from __future__ import annotations

from .core.datalog import Datalog, lit, var
from .core.log import get_logger
from .knowledge import UNKNOWN, GcpSnapshot, Unknown

logger = get_logger(__name__)

__all__ = ["hierarchy_program", "ancestors", "ancestry_chain", "descendants"]


# -- the Datalog program ------------------------------------------------------


def hierarchy_program(snapshot: GcpSnapshot) -> Datalog | None:
    """The Datalog program whose fixpoint is the ancestor closure of *snapshot*'s
    resource hierarchy, or ``None`` when the hierarchy was never captured (so
    callers abstain).

    Base facts, one triple per hierarchy record: ``node(name)``,
    ``node_type(name, type)``, and — only when the record has a non-null parent —
    ``parent(child, parent)``. The transitive closure is the recursive rule pair

        ``ancestor(C, P) :- parent(C, P).``
        ``ancestor(C, A) :- parent(C, P), ancestor(P, A).``

    which the engine's naive fixpoint computes directly. Negation appears
    nowhere, so stratification is trivially satisfied and a cyclic hierarchy
    still terminates (the closure is finite).
    """
    if snapshot.resource_hierarchy is None:
        return None
    dl = Datalog()
    for name, record in snapshot.resource_hierarchy.items():
        dl.fact("node", name)
        node_type = record.get("type")
        if node_type is not None:
            dl.fact("node_type", name, node_type)
        parent = record.get("parent")
        if parent is not None:
            dl.fact("parent", name, parent)
    c, p, a = var("c"), var("p"), var("a")
    dl.rule(lit("ancestor", c, p), [lit("parent", c, p)])
    dl.rule(lit("ancestor", c, a), [lit("parent", c, p), lit("ancestor", p, a)])
    return dl


# -- node resolution ----------------------------------------------------------


def _canonical(snapshot: GcpSnapshot, node: str) -> str | Unknown:
    """The canonical hierarchy key for *node*, resolving the ``projects/<number>``
    alias through :meth:`GcpSnapshot.hierarchy_node`.

    Returns :data:`UNKNOWN` when the hierarchy was never captured; the node's own
    name when the hierarchy was captured but holds no such node (absence is then
    a fact, and the walk/closure yields nothing); otherwise the record's own key.
    """
    record = snapshot.hierarchy_node(node)
    if record is UNKNOWN:
        return UNKNOWN
    if record is None:
        # Captured, but this node is not in the table: keep the name so the
        # walk finds no record and honestly returns an empty ancestry.
        return node
    # hierarchy_node returns the stored record object; recover its key by
    # identity so the ``projects/<number>`` alias resolves to the canonical id.
    for key, stored in (snapshot.resource_hierarchy or {}).items():
        if stored is record:
            return key
    return node  # pragma: no cover - record came from the table, so unreachable


def _walk_ancestors(snapshot: GcpSnapshot, canonical: str) -> tuple[str, ...]:
    """Walk ``parent`` links upward from *canonical* and return the ancestors
    OUTERMOST FIRST (organization at index 0, immediate parent last), EXCLUDING
    *canonical* itself.

    A visited set makes a cyclic hierarchy terminate: on meeting a node already
    seen we log a warning and stop, returning the prefix walked so far. A parent
    edge pointing at a node not itself in the table is retained (the chain ends
    there) and logged at debug — real captures scoped below the org root do this.
    """
    table = snapshot.resource_hierarchy or {}
    chain: list[str] = []  # innermost-first while walking; reversed on return
    visited = {canonical}
    current = canonical
    while True:
        record = table.get(current)
        if record is None:
            if current != canonical:
                logger.debug("hierarchy parent %r is not itself a captured node; "
                             "ancestry chain ends there", current)
            break
        parent = record.get("parent")
        if parent is None:
            break
        if parent in visited:
            logger.warning("hierarchy cycle detected walking from %r: %r -> %r "
                           "revisits an ancestor; returning the prefix walked so far",
                           canonical, current, parent)
            break
        visited.add(parent)
        chain.append(parent)
        current = parent
    return tuple(reversed(chain))


# -- accessors ----------------------------------------------------------------


def ancestors(snapshot: GcpSnapshot, node: str) -> tuple[str, ...] | Unknown:
    """The ancestors of *node*, OUTERMOST FIRST and EXCLUDING *node* itself.

    Index 0 is the organization and the last element is the immediate parent —
    the exact order hierarchical firewall policies evaluate in. Returns
    :data:`UNKNOWN` when the hierarchy was never captured; an EMPTY tuple when it
    was captured but records no parent for *node* (including a node absent from
    the table). Accepts the ``projects/<number>`` alias.
    """
    canonical = _canonical(snapshot, node)
    if canonical is UNKNOWN:
        return UNKNOWN
    return _walk_ancestors(snapshot, canonical)


def ancestry_chain(snapshot: GcpSnapshot, node: str) -> tuple[str, ...] | Unknown:
    """:func:`ancestors` with *node* itself appended — the full outermost-first
    path from the organization down to and including *node*. :data:`UNKNOWN`
    propagates from :func:`ancestors`."""
    canonical = _canonical(snapshot, node)
    if canonical is UNKNOWN:
        return UNKNOWN
    return _walk_ancestors(snapshot, canonical) + (canonical,)


def descendants(snapshot: GcpSnapshot, node: str) -> frozenset[str] | Unknown:
    """Every node having *node* among its ancestors (the closure below it),
    unordered. Returns :data:`UNKNOWN` when the hierarchy was never captured; an
    EMPTY frozenset when captured but nothing sits below *node*. Accepts the
    ``projects/<number>`` alias."""
    canonical = _canonical(snapshot, node)
    if canonical is UNKNOWN:
        return UNKNOWN
    program = hierarchy_program(snapshot)
    if program is None:  # pragma: no cover - canonical guards this already
        return UNKNOWN
    program.run()
    return frozenset(child for child, ancestor in program.query("ancestor")
                     if ancestor == canonical)
