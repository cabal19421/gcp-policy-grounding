"""Drive the real ``gcp-ground verify-policy --hook`` process boundary.

This module is the only place in the agentic suite that spawns the gate. Every
downstream adversarial family asserts through :func:`run_hook` (or its raw /
explain variants) and the sidecar :func:`ground_json`, so the process boundary
— argv, stdin, environment, exit code, the two streams — is specified once,
here, instead of being re-guessed per module.

Why a subprocess at all, when 233 in-process tests already exercise the gate:
the hook contract the editor agent actually consumes is *exit code 2 plus
stderr*, produced by a child interpreter reading a JSON event on stdin. An
in-process call to :func:`~gcp_grounding.cli.main` cannot observe argv
assembly, stdin decoding, the environment fallback, or a crash that never
reaches ``sys.exit``.

Determinism of the child environment is the load-bearing detail. The child
starts from ``os.environ`` — a developer's ``PATH``, ``HOME`` and locale must
survive — and then every environment variable this repo reads is
unconditionally removed (see :data:`SCRUBBED_ENV`), whatever the developer has
exported. ``GCP_SEC_LLM`` is then set to ``"0"`` rather than merely left unset:
:func:`sec_llm.available` is true when ``GCP_SEC_LLM=1`` *and*
``GCP_SEC_LLM_CMD`` names an on-PATH command, so a developer with both exported
would hand the child a live LLM path and break the fully-offline guarantee in a
way that reproduces on exactly one machine. Setting it explicitly also makes the
intent visible in a ``ps -e`` listing or a crash dump, where an absent variable
is invisible.

``PYTHONPATH`` is deliberately NOT stripped: the degraded-world overlays from
``tests/conftest.py`` (``no_z3_env``, ``no_tf_claims_env``) work by prepending
``tests/agentic/_blockimports`` to it. The package is importable in the child
because of ``cwd=REPO_ROOT``, not because of ``PYTHONPATH`` — ``python -m``
puts the working directory on ``sys.path``, so no editable install is needed.

Frugality: pytest's ``-p no:cacheprovider`` has no equivalent here (the child
is the CLI, not a pytest run) so the spawn is already minimal — no interpreter
flags, no cache written. What *is* enforced is the suite-wide ceiling: every
spawn in this module, from every helper, calls
:meth:`~tests.agentic.budget.SubprocessBudget.increment` on the session
``subprocess_budget`` fixture, so the ceiling lives at one place instead of
being apportioned to per-module estimates that nobody rechecks. The binding
itself is NOT this module's to make — ``tests/conftest.py`` binds it in a
session-scoped autouse fixture, so a module that imports :func:`run_hook` and
nothing else is enrolled anyway, and :func:`current_budget` RAISES while
nothing is bound rather than absorbing spawns into a counter nobody checks. The
label is the calling module's, so the per-label breakdown names an offender.

ONE SCRUB, DECLARED HERE. :data:`STDERR_ALLOWLIST` holds EXACT stderr lines
this harness provokes from the product and removes from
:attr:`HookOutcome.stderr`; :attr:`HookOutcome.stderr_raw` keeps the bytes as
emitted and ``__str__`` renders those, so nothing is hidden from a failure
report. It exists for one line: the degraded-world overlay leaves ``z3``
importable-by-``find_spec`` but not loadable, which is exactly the shape
``core/solver.py`` warns about, so a clean policy on a clean run writes 236
bytes to stderr and no ``assert_passed`` in the suite could hold. Scrubbing
changes THE MEASURING INSTRUMENT, NOT THE PRODUCT: on a machine whose solver is
installed but not initialisable — a mismatched library, a wrong-arch wheel —
the gate still writes that line to the hook's stderr once per tool call, where
the agent and the operator read it. That half is not fixed here; see
``ESC-HOOKRUNNER-NO-Z3-BANNER`` in :mod:`tests.escalations` for the product fix.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.agentic.budget import SubprocessBudget
from tests.agentic.env import ESTATE_SNAPSHOT, REPO_ROOT

__all__ = [
    "DEFAULT_TIMEOUT",
    "HookOutcome",
    "NO_Z3_FALLBACK_BANNER",
    "SCRUBBED_ENV",
    "STDERR_ALLOWLIST",
    "bind_budget",
    "bound_subprocess_budget",
    "child_env",
    "current_budget",
    "ground_json",
    "run_hook",
    "run_hook_explain",
    "run_hook_raw",
    "scrub_stderr",
]

#: Wall-clock ceiling for one child. Generous on purpose: a *hang* is the
#: failure worth catching, and a tight timeout would turn a slow CI box into a
#: flake.
DEFAULT_TIMEOUT = 60.0

#: Every environment variable this repo reads, removed from the child
#: unconditionally so a developer's exported shell state cannot change a
#: verdict. The three ``GCP_SEC_LLM*`` names are as load-bearing as the
#: snapshot one — see the module docstring.
SCRUBBED_ENV = (
    "GCP_GROUNDING_SNAPSHOT",
    "GCP_GROUNDING_BASH_POLICY",
    "GCP_GROUNDING_ABSTAIN_NOTES",
    "GCP_GROUNDING_REQUIREMENTS",
    "GCP_TEST_BLOCK_IMPORTS",
    "GCP_SEC_LLM",
    "GCP_SEC_LLM_CMD",
    "GCP_SEC_LLM_TIMEOUT",
)

#: ``core/solver.py:116-120``'s fallback warning, as the degraded-world overlay
#: provokes it: ``sitecustomize`` returns a spec whose loader raises, so
#: ``find_spec("z3")`` succeeds, ``Z3Solver()`` raises ``ImportError``, and
#: ``get_solver`` logs at WARNING. No ``setup_logging`` call means logging's
#: ``lastResort`` handler writes the bare message to stderr — one line, 236
#: bytes with its newline, on every child in the no-z3 world.
NO_Z3_FALLBACK_BANNER = (
    "z3 package found but failed to initialize (ImportError: import of z3 is "
    "blocked by GCP_TEST_BLOCK_IMPORTS (degraded-world test harness)) — "
    "falling back to the builtin solver; arity answers are identical, only "
    "--explain output differs"
)

#: EXACT stderr lines removed from :attr:`HookOutcome.stderr`. This tuple may
#: only ever SHRINK — its length is pinned in
#: ``tests/test_gcp_hookrunner.py``, every entry is checked there against a line
#: a real child emits, and a test drives stderr bytes from outside it through
#: ``assert_passed`` to prove they still fail. Whole lines, never substrings: a
#: prefix match would swallow a real finding that happened to quote a banner.
STDERR_ALLOWLIST = (NO_Z3_FALLBACK_BANNER,)

_ALLOWED_LINES = frozenset(STDERR_ALLOWLIST)


def scrub_stderr(text: str) -> str:
    """*text* with every :data:`STDERR_ALLOWLIST` line removed, byte-exact.

    Splitting on ``"\\n"`` rather than :meth:`str.splitlines` on purpose:
    ``splitlines`` also breaks on form feeds and ``\\u2028``, which would let
    the rejoin silently rewrite bytes the child really emitted.
    """
    if not text:
        return text
    return "\n".join(line for line in text.split("\n")
                     if line not in _ALLOWED_LINES)


#: Sentinel default for the ``snapshot`` parameter. ``snapshot=None`` means
#: "spawn with NO ``--snapshot``", which is the fail-open arm; omitting the
#: parameter means "the estate snapshot". Those two cases are different tests,
#: so they cannot share ``None``.
_DEFAULT = object()

#: This package's own dotted prefix. Frames from it are HELPER frames: a driver
#: here must not mask the test module that drove it in the label breakdown.
_PACKAGE = __name__.rpartition(".")[0]

# The counter spawns are recorded against, bound by tests/conftest.py's
# session-scoped autouse fixture. There is deliberately NO module-level
# fallback: one existed, nothing ever called its ``check()``, and its comment
# claimed it "still enforces the same ceiling" — so a module that imported
# run_hook without the opt-in fixture spawned children into a counter that
# enforced nothing, silently.
_budget: SubprocessBudget | None = None


def current_budget() -> SubprocessBudget:
    """The counter spawns are recorded against.

    Raises ``RuntimeError`` while nothing is bound. Absorbing the spawn into a
    private counter would be the same silent hole, one indirection further
    down: unbound means the ceiling is not being enforced, and that has to be
    loud.
    """
    if _budget is None:
        raise RuntimeError(
            "no subprocess budget is bound: tests/conftest.py binds the "
            "session `subprocess_budget` in a session-scoped autouse fixture, "
            "so a spawn reaching here unbound is running outside that session "
            "and against no ceiling at all")
    return _budget


def bind_budget(budget: SubprocessBudget | None) -> SubprocessBudget | None:
    """Point the spawn counter at *budget* (``None`` unbinds); return the
    previous one so a caller can restore it."""
    global _budget
    previous, _budget = _budget, budget
    return previous


def _calling_label() -> str:
    """The module that ASKED for this spawn.

    Walks out through this package's own frames, so the breakdown names the
    test module rather than ``tests.agentic.hookrunner`` — which is present in
    every single spawn and can therefore never be the offender. A driver in
    ``tests.agentic`` (a fake agent, an assertion wrapper) is skipped for the
    same reason. The first frame outside this package, or failing that the
    first frame outside this module, is the answer.
    """
    frame = sys._getframe(1)
    outside_module = None
    while frame is not None:
        name = frame.f_globals.get("__name__") or ""
        if name and name != __name__ and outside_module is None:
            outside_module = name
        if name and name != _PACKAGE and not name.startswith(_PACKAGE + "."):
            return name
        frame = frame.f_back
    return outside_module or __name__


@pytest.fixture(autouse=True)
def bound_subprocess_budget(subprocess_budget):
    """Retained for the modules that import it; it no longer decides anything.

    The binding moved to ``tests/conftest.py`` as a session-scoped autouse
    fixture precisely because this one was OPT-IN — a module that imported
    :func:`run_hook` and forgot this name spawned children the session ceiling
    never saw. Re-binding the same object here is a no-op, kept so the existing
    ``from tests.agentic.hookrunner import bound_subprocess_budget`` imports
    keep working.
    """
    previous = bind_budget(subprocess_budget)
    try:
        yield subprocess_budget
    finally:
        bind_budget(previous)


@dataclass(frozen=True)
class HookOutcome:
    """One completed child run, with everything needed to debug it in place.

    Every assertion helper in :mod:`tests.agentic.asserts` passes
    ``str(outcome)`` as the pytest assertion message, so a failure is
    diagnosable from the report alone — no rerun with prints added.
    """

    exit_code: int
    stdout: str
    #: The child's stderr with the :data:`STDERR_ALLOWLIST` lines removed —
    #: what every assertion reads.
    stderr: str
    argv: tuple[str, ...]
    #: The event as a mapping, or ``None`` for :func:`run_hook_raw` (whose
    #: payload may not be a JSON object at all) and for non-hook spawns.
    event: Mapping | None = None
    #: The exact bytes written to the child's stdin.
    stdin_bytes: bytes = field(default=b"")
    #: The child's stderr EXACTLY as emitted, scrub included. ``None`` on a
    #: hand-built outcome, where there is no child and nothing to distinguish.
    stderr_raw: str | None = None

    def __str__(self) -> str:
        raw = self.stderr if self.stderr_raw is None else self.stderr_raw
        lines = [
            f"argv: {' '.join(self.argv)}",
            f"exit code: {self.exit_code}",
            f"stdin: {len(self.stdin_bytes)} bytes",
            f"stdout:\n{self.stdout or '  (empty)'}",
            f"stderr:\n{raw or '  (empty)'}",
        ]
        if raw != self.stderr:
            # Say which lines the assertions did not see, and why they exist.
            filtered = [line for line in raw.split("\n")
                        if line in _ALLOWED_LINES]
            lines.append(
                f"(stderr above is RAW; {len(filtered)} allowlisted harness "
                f"line(s) were filtered before the assertions read it: "
                f"{filtered})")
        return "\n".join(lines)


def child_env(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """The deterministic child environment: ``os.environ``, minus every name
    in :data:`SCRUBBED_ENV`, plus an explicit ``GCP_SEC_LLM=0``, plus the
    caller's *overrides* last (so a degraded-world overlay can put
    ``GCP_TEST_BLOCK_IMPORTS`` back deliberately)."""
    result = dict(os.environ)
    for name in SCRUBBED_ENV:
        result.pop(name, None)
    result["GCP_SEC_LLM"] = "0"
    if overrides:
        result.update({str(k): str(v) for k, v in overrides.items()})
    return result


def _spawn(argv, payload: bytes, *, event=None, env=None,
           timeout: float = DEFAULT_TIMEOUT) -> HookOutcome:
    """Run *argv* with *payload* on stdin and capture everything.

    ``text=False`` with an explicit ``errors="replace"`` decode: a child that
    emits non-UTF-8 on either stream must not crash the *test*, because the
    bytes it emitted are exactly the evidence the failure needs.
    A :class:`subprocess.TimeoutExpired` deliberately propagates — a hung gate
    is a finding, not something to fold into an exit code.
    """
    argv = tuple(str(part) for part in argv)
    current_budget().increment(_calling_label())
    proc = subprocess.run(
        list(argv),
        input=payload,
        capture_output=True,
        cwd=str(REPO_ROOT),
        env=child_env(env),
        timeout=timeout,
        text=False,
    )
    raw_stderr = proc.stderr.decode("utf-8", errors="replace")
    return HookOutcome(
        exit_code=proc.returncode,
        stdout=proc.stdout.decode("utf-8", errors="replace"),
        stderr=scrub_stderr(raw_stderr),
        argv=argv,
        event=event,
        stdin_bytes=payload,
        stderr_raw=raw_stderr,
    )


def _hook_argv(snapshot, extra_argv=()) -> list:
    argv = [sys.executable, "-m", "gcp_grounding", "verify-policy", "--hook"]
    if snapshot is not None:
        argv += ["--snapshot", str(snapshot)]
    return argv + list(extra_argv)


def _resolve_snapshot(snapshot) -> Path | str | None:
    return ESTATE_SNAPSHOT if snapshot is _DEFAULT else snapshot


def run_hook(event: Mapping, *, snapshot=_DEFAULT, extra_argv=(), env=None,
             timeout: float = DEFAULT_TIMEOUT) -> HookOutcome:
    """Spawn the gate in ``--hook`` mode with *event* as the stdin JSON.

    *snapshot* defaults to the estate snapshot; passing ``None`` explicitly
    spawns with no ``--snapshot`` at all, which — since
    ``GCP_GROUNDING_SNAPSHOT`` is scrubbed from the child — is how the
    fail-open arm gets exercised.
    """
    resolved = _resolve_snapshot(snapshot)
    return _spawn(
        _hook_argv(resolved, extra_argv),
        json.dumps(event).encode("utf-8"),
        event=event,
        env=env,
        timeout=timeout,
    )


def run_hook_raw(payload: bytes, *, snapshot=_DEFAULT, extra_argv=(), env=None,
                 timeout: float = DEFAULT_TIMEOUT) -> HookOutcome:
    """:func:`run_hook` with the caller supplying the exact stdin bytes.

    For the events that are not events: empty, malformed JSON, non-UTF-8, a
    JSON ``null``, a JSON array, a 5MB document. The outcome's ``event`` is
    ``None`` because there may be no mapping to record.
    """
    resolved = _resolve_snapshot(snapshot)
    return _spawn(
        _hook_argv(resolved, extra_argv),
        payload,
        event=None,
        env=env,
        timeout=timeout,
    )


def run_hook_explain(event: Mapping, **kwargs) -> HookOutcome:
    """:func:`run_hook` with ``--explain``.

    ``cli.py:183-184`` prints the explain lines BEFORE the ``report.ok``
    check, so ``--explain`` is the one channel already visible on an exit-0
    hook run today: its first stderr line is
    ``"z3 constraints generated this run [<backend>]:"``. Without it an
    exit-0 hook run is silent by design, and there is nothing to assert on.
    """
    extra_argv = ("--explain",) + tuple(kwargs.pop("extra_argv", ()))
    return run_hook(event, extra_argv=extra_argv, **kwargs)


def ground_json(path, *, snapshot=_DEFAULT, baseline=None, env=None,
                timeout: float = DEFAULT_TIMEOUT) -> dict:
    """THE ABSTAIN SIDECAR: the same gate, in NORMAL mode, ``--format json``.

    The hook run proves the exit-code and stream contract; this proves the
    *bucket and the message*. A hook run that passes in silence — which every
    abstain does, honestly — has no stdout to assert verdict text against, and
    teaching the hook to print on success would change production behaviour to
    suit a test. So the sidecar runs the same document through the same
    :func:`~gcp_grounding.preflight.ground_policy` and reads the machine
    document instead.

    Returns the parsed ``gcp-grounding-report/1`` document: ``schema``, ``ok``,
    ``backend``, ``captured_at``, ``source``, ``summary``, ``verdicts``. The
    returncode must be 0 (ok) or 1 (ungrounded/contradicted); a 2 is a usage
    error — an unreadable snapshot, a bad flag — and fails here rather than
    being mistaken for a verdict.
    """
    resolved = _resolve_snapshot(snapshot)
    argv = [sys.executable, "-m", "gcp_grounding", "verify-policy", str(path)]
    if resolved is not None:
        argv += ["--snapshot", str(resolved)]
    if baseline is not None:
        argv += ["--baseline", str(baseline)]
    argv += ["--format", "json"]
    outcome = _spawn(argv, b"", env=env, timeout=timeout)
    assert outcome.exit_code in (0, 1), (
        f"ground_json expected exit 0 or 1 (a verdict), got {outcome.exit_code} "
        f"(2 is a usage error, not a verdict)\n{outcome}")
    try:
        return json.loads(outcome.stdout)
    except ValueError as exc:
        raise AssertionError(
            f"ground_json could not parse the report document ({exc})\n{outcome}"
        ) from None
