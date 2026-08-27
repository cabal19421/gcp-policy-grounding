"""Suite-wide subprocess spawn budget.

The repo's only oracle is the *full* test run; if the number of child processes
the agentic suite spawns grows unbounded, a 0.28s run turns into several minutes
and the oracle silently stops being run at all. Every spawn helper in
``tests.agentic.hookrunner`` calls :meth:`SubprocessBudget.increment` on the
session-scoped ``subprocess_budget`` fixture, and that fixture fails at session
teardown if the total exceeded the ceiling — with the per-label counts in the
message, so the offending module names itself instead of the ceiling being
apportioned by guesswork.

Kept here as a plain class rather than inside the fixture so a test can drive a
stub counter past a deliberately tiny ceiling and exercise the teardown check
without actually spawning hundreds of processes.
"""

from __future__ import annotations


class SubprocessBudget:
    """A labelled spawn counter with a hard ceiling checked on demand."""

    #: The suite-wide default ceiling, shared by every spawn helper.
    #:
    #: RE-DERIVED FOR THE INTEGRATED SUITE. 260 was the ceiling measured when
    #: this counter landed, against the agentic modules that existed on ONE
    #: branch. The integrated tree carries nineteen spawn-using modules, each
    #: sized under its own MODULE_SPAWN_CAP, and their union measures 408 spawns
    #: in a full run that still completes in well under a minute — so the
    #: property this ceiling exists to protect (the full run stays a usable
    #: oracle) holds, while the old number cannot be met by any subset of the
    #: modules without deleting cases. The ceiling is therefore the measured
    #: integrated total plus headroom, and it still BITES: it is a hard aggregate
    #: cap, and each module's own teardown cap is unchanged and unrelaxed.
    #: 450 -> 466 when tx-agentic-tf-block (8 spawns) and tx-agentic-tf-drift
    #: (6) landed: the measured total moved to 456, and the ceiling moved by
    #: exactly the two modules' declared budgets plus two of headroom.
    #: 466 -> 478 when the IAM-deny catalogue (gx-iam-deny-pair) landed: five
    #: cases at two children each measure 10, and the ceiling moved by exactly
    #: that module's declared MODULE_SPAWN_CAP of 12 (10 plus two of headroom).
    #: 478 -> 488 when the effective org-policy catalogue landed: eight hook
    #: children measured (every sidecar report is the in-process CLI mirror,
    #: so it costs nothing), and the ceiling moved by exactly that module's
    #: declared MODULE_SPAWN_CAP of 10 (8 plus two of headroom).
    MAX_SUBPROCESS_SPAWNS = 488

    #: The env name the mutation contract's machinery stamps on every child it
    #: spawns. A spawn carrying it is counted against :attr:`max_marked` — the
    #: contract's own ceiling, scaled to its register — and never against the
    #: one above, left untouched. Neither is raisable by a seeding task.
    CHILD_MARK = "GCP_MUTATION_CONTRACT_CHILD"

    #: Zero: a run never reaching the machinery marks nothing, and the exact
    #: accounting is handed in by ``tests/conftest.py`` from the register.
    MAX_MARKED_SPAWNS = 0

    def __init__(self, max_spawns: int | None = None,
                 max_marked: int | None = None) -> None:
        self.max_spawns = self.MAX_SUBPROCESS_SPAWNS if max_spawns is None else max_spawns
        self.max_marked = self.MAX_MARKED_SPAWNS if max_marked is None else max_marked
        self.counts: dict[str, int] = {}
        self.marked: dict[str, int] = {}

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def marked_total(self) -> int:
        return sum(self.marked.values())

    def increment(self, label: str, env=None) -> int:
        """Record one spawn attributed to *label*; return the running total.
        The mark is read from *env*, the child's OWN environment, so routing
        follows the process spawned; :attr:`total` is the UNMARKED half."""
        marked = env is not None and str(env.get(self.CHILD_MARK, "")) == "1"
        book = self.marked if marked else self.counts
        book[label] = book.get(label, 0) + 1
        return self.total + self.marked_total

    def check(self) -> None:
        """Raise ``AssertionError`` naming the per-label counts if the total
        exceeded EITHER ceiling. Called at session teardown, and directly by the
        plumbing test against a stub counter with a tiny ceiling."""
        self._ceiling("subprocess spawn", self.total, self.max_spawns, self.counts)
        self._ceiling("mutation-contract spawn", self.marked_total,
                      self.max_marked, self.marked)

    @staticmethod
    def _ceiling(what, total, ceiling, counts) -> None:
        if total > ceiling:
            breakdown = ", ".join(
                f"{label}={count}" for label, count in sorted(counts.items())
            ) or "no labels"
            raise AssertionError(
                f"{what} budget exceeded: {total} spawns > "
                f"ceiling {ceiling} ({breakdown})"
            )
