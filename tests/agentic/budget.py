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
    MAX_SUBPROCESS_SPAWNS = 450

    def __init__(self, max_spawns: int | None = None) -> None:
        self.max_spawns = self.MAX_SUBPROCESS_SPAWNS if max_spawns is None else max_spawns
        self.counts: dict[str, int] = {}

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def increment(self, label: str) -> int:
        """Record one spawn attributed to *label*; return the running total."""
        self.counts[label] = self.counts.get(label, 0) + 1
        return self.total

    def check(self) -> None:
        """Raise ``AssertionError`` naming the per-label counts if the total
        exceeded the ceiling. Called at session teardown, and directly by the
        plumbing test against a stub counter with a tiny ceiling."""
        if self.total > self.max_spawns:
            breakdown = ", ".join(
                f"{label}={count}" for label, count in sorted(self.counts.items())
            ) or "no labels"
            raise AssertionError(
                f"subprocess spawn budget exceeded: {self.total} spawns > "
                f"ceiling {self.max_spawns} ({breakdown})"
            )
