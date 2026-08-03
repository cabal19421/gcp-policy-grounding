"""Drive the real ``gcp-ground verify-policy --hook`` process boundary.

This module is the only place in the agentic suite that spawns the gate. Every
downstream adversarial family asserts through :func:`run_hook` (or its raw /
explain variants) and the sidecar :func:`ground_json`, so the process boundary
— argv, stdin, environment, exit code, the two streams — is specified once,
here, instead of being re-guessed per module.

Why a subprocess at all, when 233 in-process tests already exercise the gate:
the hook contract Claude Code actually consumes is *exit code 2 plus stderr*,
produced by a child interpreter reading a JSON event on stdin. An in-process
call to :func:`~gcp_grounding.cli.main` cannot observe argv assembly, stdin
decoding, the environment fallback, or a crash that never reaches
``sys.exit``.

Determinism of the child environment is the load-bearing detail. The child
starts from ``os.environ`` — a developer's ``PATH``, ``HOME`` and locale must
survive — and then every environment variable this repo reads is
unconditionally removed (see :data:`SCRUBBED_ENV`), whatever the developer has
exported. ``GCP_SEC_LLM`` is then set to ``"0"`` rather than merely left unset:
:func:`sec_llm.available` is true when ``GCP_SEC_LLM=1`` *and*
``shutil.which("claude")`` is non-None, so a developer with both exported would
hand the child a live LLM path and break the fully-offline guarantee in a way
that reproduces on exactly one machine. Setting it explicitly also makes the
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
being apportioned to per-module estimates that nobody rechecks.
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
    "SCRUBBED_ENV",
    "bind_budget",
    "bound_subprocess_budget",
    "child_env",
    "current_budget",
    "ground_json",
    "run_hook",
    "run_hook_explain",
    "run_hook_raw",
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
    "GCP_SEC_LLM_MODEL",
    "GCP_SEC_LLM_TIMEOUT",
)

#: Sentinel default for the ``snapshot`` parameter. ``snapshot=None`` means
#: "spawn with NO ``--snapshot``", which is the fail-open arm; omitting the
#: parameter means "the estate snapshot". Those two cases are different tests,
#: so they cannot share ``None``.
_DEFAULT = object()

#: Budget label every spawn from this module is attributed to.
BUDGET_LABEL = __name__

# Fallback counter used when no session fixture is bound (a helper called from
# a plain script, or before ``bound_subprocess_budget`` is set up). It still
# enforces the same ceiling; it just is not shared with the rest of the run.
_budget = SubprocessBudget()


def current_budget() -> SubprocessBudget:
    """The counter this module's spawns are recorded against."""
    return _budget


def bind_budget(budget: SubprocessBudget) -> SubprocessBudget:
    """Point this module's spawn counter at *budget*; return the previous one
    so a caller can restore it."""
    global _budget
    previous, _budget = _budget, budget
    return previous


@pytest.fixture(autouse=True)
def bound_subprocess_budget(subprocess_budget):
    """Bind this module's spawns to the session ``subprocess_budget``.

    Import this name into a test module (``from tests.agentic.hookrunner
    import bound_subprocess_budget  # noqa: F401``) and every spawn that
    module makes is counted at the one suite-wide ceiling. It is autouse, so
    no test has to remember to request it.
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
    stderr: str
    argv: tuple[str, ...]
    #: The event as a mapping, or ``None`` for :func:`run_hook_raw` (whose
    #: payload may not be a JSON object at all) and for non-hook spawns.
    event: Mapping | None = None
    #: The exact bytes written to the child's stdin.
    stdin_bytes: bytes = field(default=b"")

    def __str__(self) -> str:
        return "\n".join([
            f"argv: {' '.join(self.argv)}",
            f"exit code: {self.exit_code}",
            f"stdin: {len(self.stdin_bytes)} bytes",
            f"stdout:\n{self.stdout or '  (empty)'}",
            f"stderr:\n{self.stderr or '  (empty)'}",
        ])


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
    current_budget().increment(BUDGET_LABEL)
    proc = subprocess.run(
        list(argv),
        input=payload,
        capture_output=True,
        cwd=str(REPO_ROOT),
        env=child_env(env),
        timeout=timeout,
        text=False,
    )
    return HookOutcome(
        exit_code=proc.returncode,
        stdout=proc.stdout.decode("utf-8", errors="replace"),
        stderr=proc.stderr.decode("utf-8", errors="replace"),
        argv=argv,
        event=event,
        stdin_bytes=payload,
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
