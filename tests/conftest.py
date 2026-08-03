"""Shared pytest fixtures for the GCP grounding suite.

Fixtures only. Plain constants, probes and helpers live in
:mod:`tests.agentic.env` (importable at decorator time, where fixtures cannot
reach); the subprocess counter lives in :mod:`tests.agentic.budget`. This module
deliberately imports nothing from ``tests.agentic.hookrunner`` or
``tests.agentic.fake_agent`` — those land in later tasks, and importing them
here would break collection until then.

The repo-root ``conftest.py`` (whose sole job is inserting the repo root onto
``sys.path``) is loaded before this one, so ``from tests.agentic import env``
resolves here.
"""

from __future__ import annotations

import json
import os
import re

import pytest

from gcp_grounding.knowledge import GcpSnapshot
from tests.agentic import env
from tests.agentic.budget import SubprocessBudget


# -- static paths -------------------------------------------------------------


@pytest.fixture(scope="session")
def repo_root():
    return env.REPO_ROOT


@pytest.fixture(scope="session")
def fixtures_dir():
    return env.FIXTURES


@pytest.fixture(scope="session")
def policies_dir():
    return env.POLICIES


@pytest.fixture(scope="session")
def agentic_dir():
    return env.AGENTIC


@pytest.fixture(scope="session")
def toy_snapshot_path():
    return env.TOY_SNAPSHOT


# -- the estate snapshot ------------------------------------------------------


@pytest.fixture(scope="session")
def estate_snapshot_path(tmp_path_factory):
    """Path to the agentic estate snapshot.

    Once the domain knowledge work lands (``HAVE_ESTATE_CATEGORY``), this is the
    base snapshot with the overlay's domain categories merged in, written into a
    session tmp dir. Until then it is the committed five-category snapshot,
    unchanged.
    """
    if not env.HAVE_ESTATE_CATEGORY:
        return env.ESTATE_SNAPSHOT
    merged = env.merged_estate_document()
    path = tmp_path_factory.mktemp("estate") / "agentic_snapshot_merged.json"
    path.write_text(json.dumps(merged, indent=2, sort_keys=True), encoding="utf-8")
    return path


@pytest.fixture(scope="session")
def estate_snapshot(estate_snapshot_path):
    return GcpSnapshot.load(estate_snapshot_path)


# -- snapshot variants --------------------------------------------------------


def _variant_slug(drop, captured_at, extra) -> str:
    """A stable, filesystem-safe name derived from the variant's arguments, so
    repeated calls with the same arguments write the same file."""
    parts = []
    if drop:
        parts.append("drop-" + "-".join(sorted(drop)))
    if captured_at:
        parts.append("at-" + captured_at)
    if extra:
        parts.append("extra-" + "-".join(sorted(extra)))
    slug = "_".join(parts) or "base"
    return re.sub(r"[^A-Za-z0-9._-]", "_", slug) + ".json"


@pytest.fixture
def snapshot_variant(estate_snapshot_path, tmp_path):
    """Factory: derive a snapshot from the estate snapshot with top-level
    categories dropped, ``captured_at`` overridden and/or extra keys merged.

    This is how the uncaptured-principals and stale-snapshot cases get their
    snapshots, without a committed fixture per case.
    """

    def make(*, drop=(), captured_at=None, extra=None):
        data = json.loads(estate_snapshot_path.read_text(encoding="utf-8"))
        for category in drop:
            data.pop(category, None)
        if captured_at is not None:
            data["captured_at"] = captured_at
        if extra:
            data.update(extra)
        path = tmp_path / _variant_slug(drop, captured_at, extra)
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return path

    return make


# -- the fake agent's working tree --------------------------------------------


@pytest.fixture
def agent_workdir(tmp_path):
    """A fresh ``tmp_path/agent`` directory holding an empty
    ``transcript.jsonl`` — the working tree a scripted fake agent runs in."""
    workdir = tmp_path / "agent"
    workdir.mkdir()
    (workdir / "transcript.jsonl").write_text("", encoding="utf-8")
    return workdir


# -- degraded-world child env -------------------------------------------------


@pytest.fixture
def blocked_import_env():
    """Factory: an env overlay that makes named modules fail to import in a child.

    ``make(*names)`` returns a mapping to merge into a child process's
    environment: a ``PYTHONPATH`` prepending :data:`env.BLOCKIMPORTS_DIR` (so the
    child auto-imports the degraded-world ``sitecustomize``) plus
    ``GCP_TEST_BLOCK_IMPORTS`` naming the modules to block, joined by commas. The
    convenience aliases ``no_z3_env`` and ``no_tf_claims_env`` carry the two
    overlays this suite uses most.
    """

    def make(*names):
        existing = os.environ.get("PYTHONPATH", "")
        entries = [str(env.BLOCKIMPORTS_DIR)]
        if existing:
            entries.append(existing)
        return {
            "PYTHONPATH": os.pathsep.join(entries),
            "GCP_TEST_BLOCK_IMPORTS": ",".join(names),
        }

    make.no_z3_env = make("z3")
    make.no_tf_claims_env = make("gcp_grounding.tf_claims")
    return make


@pytest.fixture
def no_z3_env(blocked_import_env):
    """The degraded-world overlay that hides z3 from a child — the solver
    degrades to backend ``builtin`` rather than crashing."""
    return blocked_import_env("z3")


@pytest.fixture
def no_tf_claims_env(blocked_import_env):
    """The degraded-world overlay that hides ``gcp_grounding.tf_claims`` from a
    child, so ``preflight._tf_plan_extractor()`` returns ``None`` and the gate
    emits the honest ``unverified``."""
    return blocked_import_env("gcp_grounding.tf_claims")


# -- session-wide hygiene the suite cannot get right per-module ---------------


@pytest.fixture(scope="session", autouse=True)
def _scrub_sec_llm_env():
    """Guarantee the fully-offline contract for the whole run.

    ``sec_llm.available()`` is True when ``GCP_SEC_LLM=1`` and
    ``shutil.which("claude")`` is non-None, so a developer with both could
    otherwise reach the default runner from any in-process test that touches the
    sec-llm path — for reasons unrelated to that test's intent.
    ``hookrunner.run_hook`` scrubs the same three names from its *child* env;
    this fixture covers the in-process half. It runs after collection, so a
    module that set these at import time still sees them gone inside every test.
    """
    for name in ("GCP_SEC_LLM", "GCP_SEC_LLM_MODEL", "GCP_SEC_LLM_TIMEOUT"):
        os.environ.pop(name, None)


@pytest.fixture(scope="session")
def subprocess_budget():
    """The suite-wide subprocess spawn counter. Every spawn helper in
    ``hookrunner`` calls ``.increment(<label>)``; at session teardown this
    asserts the total stayed under
    :data:`SubprocessBudget.MAX_SUBPROCESS_SPAWNS`, so an unbounded run cannot
    silently turn the sub-second oracle into a minutes-long one that stops being
    run."""
    budget = SubprocessBudget()
    yield budget
    budget.check()
