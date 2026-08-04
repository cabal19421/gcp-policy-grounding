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
    MAX_SUBPROCESS_SPAWNS = 260

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
