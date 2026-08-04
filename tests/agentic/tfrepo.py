"""A temp terraform repo, built from ONE committed corpus, for the three-input
agentic cases.

This module EXTENDS the agentic suite and duplicates none of it. The hook
runners, the JSON grounding sidecar, the hook-outcome type, every honesty
assertion, the proposal type, the fake agent, the subprocess budget and every
environment constant and capability probe already in the suite come from
:mod:`tests.agentic.hookrunner`, :mod:`tests.agentic.asserts`,
:mod:`tests.agentic.fake_agent`, :mod:`tests.agentic.budget` and
:mod:`tests.agentic.env` BY IMPORT. What is here is only what those modules do
not have: a terraform working tree an agent can edit, the probes for the
current-state stack that tree exercises, and the four helpers that keep the case
modules declarative.

WHY THE PROBES LIVE HERE. ``tests/agentic/env.py`` and ``tests/conftest.py`` are
FROZEN for this task and for the four case modules that consume it, so the
current-state probes cannot be added there; keeping them in this module is what
makes this document's files disjoint from the rest of the suite. Every probe
below is a plain module-level ``bool`` computed inside a ``try``/``except`` that
can never raise at import — the same discipline ``env.py`` uses, so a missing
dependency degrades a probe to ``False`` instead of breaking collection. Every
agentic assertion in this document BRANCHES on them; none of them skips.

THE TWO ``sec_*`` PROBES exist so a benign case can exercise the THIRD input — a
compiled ``sec_requirements`` promise judged against a terraform-derived current
state through the real hook — without taking a hard dependency on the whole sec
chain and stranding itself behind more of it.

THE CORPUS is ``tests/fixtures/gcp/agentic/tf/base/``: three small, reviewable,
obviously synthetic files that are internally consistent with the agentic
snapshot and estate overlay, so no benign case blocks for an unrelated reason.
It is THE ONE PERMITTED SECOND HAND-WRITTEN v4 TFSTATE in this document, and the
exception is deliberate: it must model a DIFFERENT estate from
``tests/fixtures/gcp/tf/`` — the agentic overlay, whose principals, project
number and rule set every benign case depends on — and it deliberately carries a
present-in-state-but-not-in-config resource and a config-only new resource that
the main tree must not have. Deriving one tree from the other would couple two
estates that exist in order to differ. What removes the rot risk is not shared
bytes but the SHARED PIN: ``tests/test_gcp_agentic_tf_plumbing.py`` carries the
identical both-directions fixture-consistency assertion that
``tests/test_gcp_estate.py`` carries for the main tree, so a record-schema or
key-spelling change fails loudly in TWO named places. NO THIRD hand-written
tfstate is permitted: a case module needing a variant derives it from this base
through :func:`variant`.

SUBPROCESS BUDGET. The agentic plumbing enforces a session-wide ceiling of
``budget.SubprocessBudget.MAX_SUBPROCESS_SPAWNS`` (260) spawns. THIS DOCUMENT
SPENDS AT MOST 50 OF THEM: about 14 in the blocking cases, about 18 in the
benign cases including the two promise arms, about 8 in the drift cases, about 6
in the source-reconciliation cases and about 4 here — of which
``tests/test_gcp_agentic_tf_plumbing.py`` actually spends two, both in one
module-scoped fixture. Every spawn goes through :mod:`tests.agentic.hookrunner`,
which already increments the budget, so nothing in this module counts anything
itself.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from tests.agentic import env
from tests.agentic.fake_agent import Proposal

__all__ = [
    "BASE",
    "CONFIG_NAME",
    "CONFIG_TEMPLATE",
    "STATE_NAME",
    "TF_JSON_NAME",
    "TF_NAME",
    "SNAPSHOT_NAME",
    "ASOF",
    "PROBES",
    "HAVE_ENGINE",
    "HAVE_SOURCES",
    "HAVE_BASELINE",
    "HAVE_DISCOVERY",
    "HAVE_EXPLAIN_STATE",
    "HAVE_ESTATE",
    "HAVE_RECONCILED",
    "HAVE_SEC_RULES",
    "HAVE_SEC_DOMAINS",
    "HAVE_HCL_READER",
    "HAVE_STATE_FLAG",
    "TfRepo",
    "build_tf_repo",
    "hook_argv",
    "merged_snapshot_document",
    "proposal_for",
    "render_hcl",
    "variant",
]

# -- the corpus ---------------------------------------------------------------

#: The committed base corpus. Three files, deliberately small: the independent
#: verifier sees a 20,000-character diff prefix and ``tests/fixtures/...`` sorts
#: before ``tests/test_...``, so every byte here is a byte of the acceptance
#: module the verifier does not see.
BASE = env.AGENTIC / "tf" / "base"

#: The config template as COMMITTED. It is copied to the dot-prefixed
#: :data:`CONFIG_NAME` inside the temp repo, so the reviewable fixture is not
#: itself a hidden file.
CONFIG_TEMPLATE = "gcp-grounding.json"

#: What that template is called inside a built repo — the one name
#: ``gcp_grounding.discovery`` walks up looking for.
CONFIG_NAME = ".gcp-grounding.json"

STATE_NAME = "terraform.tfstate"
TF_JSON_NAME = "main.tf.json"
TF_NAME = "main.tf"
SNAPSHOT_NAME = "agentic_snapshot.json"

#: One hour after the agentic snapshot's capture time, so NOTHING is stale
#: unless a case makes it so. Every case passes it through :func:`hook_argv`.
ASOF = (datetime.fromisoformat(env.ESTATE_CAPTURED_AT.replace("Z", "+00:00"))
        + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- capability probes --------------------------------------------------------


def _module_available(name: str) -> bool:
    """``find_spec(name) is not None``, folded into a bool that can never raise
    at import — a missing PARENT package would otherwise raise."""
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


HAVE_ENGINE = _module_available("gcp_grounding.engine")
HAVE_SOURCES = _module_available("gcp_grounding.sources")
HAVE_BASELINE = _module_available("gcp_grounding.baseline")
HAVE_DISCOVERY = _module_available("gcp_grounding.discovery")
HAVE_EXPLAIN_STATE = _module_available("gcp_grounding.explain_state")
HAVE_ESTATE = _module_available("gcp_grounding.estate")
HAVE_RECONCILED = _module_available("gcp_grounding.reconciled")
HAVE_SEC_RULES = _module_available("gcp_grounding.sec_rules")
HAVE_SEC_DOMAINS = _module_available("gcp_grounding.sec_domains")
HAVE_HCL_READER = _module_available("gcp_grounding.tfsource.hcl")

# The one BEHAVIOURAL probe: whether the parser this suite spawns actually
# accepts the terraform-state flag. ``find_spec`` cannot answer that — the
# module can exist with the flag absent — so a throwaway argv is parsed instead.
# argparse exits through ``SystemExit`` (a BaseException, NOT an Exception) and
# prints its usage to stderr on failure, so both are caught and the stream is
# swallowed: a probe that writes to stderr at import time is noise in every
# other module's failure report.
try:
    from gcp_grounding.cli import build_parser as _build_parser

    with contextlib.redirect_stderr(io.StringIO()):
        _build_parser().parse_args(
            ["verify-policy", "doc.json", "--snapshot", "snapshot.json",
             "--terraform-state", "terraform.tfstate"])
    HAVE_STATE_FLAG = True
except (Exception, SystemExit):
    HAVE_STATE_FLAG = False

#: Every probe by name, so a case module can assert the whole set is boolean
#: without restating it.
PROBES = {
    "HAVE_ENGINE": HAVE_ENGINE,
    "HAVE_SOURCES": HAVE_SOURCES,
    "HAVE_BASELINE": HAVE_BASELINE,
    "HAVE_DISCOVERY": HAVE_DISCOVERY,
    "HAVE_EXPLAIN_STATE": HAVE_EXPLAIN_STATE,
    "HAVE_ESTATE": HAVE_ESTATE,
    "HAVE_RECONCILED": HAVE_RECONCILED,
    "HAVE_SEC_RULES": HAVE_SEC_RULES,
    "HAVE_SEC_DOMAINS": HAVE_SEC_DOMAINS,
    "HAVE_HCL_READER": HAVE_HCL_READER,
    "HAVE_STATE_FLAG": HAVE_STATE_FLAG,
}


# -- the built repo -----------------------------------------------------------


@dataclass(frozen=True)
class TfRepo:
    """One built terraform working tree: the root an agent edits in, and the
    absolute path of every file inside it a case module names.

    ``tf_path`` is ``None`` when no equivalent ``main.tf`` was written — which
    is the honest answer when the HCL reader is not part of the checkout, and
    is why it is a path-or-``None`` rather than a path that may not exist.
    """

    root: Path
    config_path: Path
    state_path: Path
    tf_json_path: Path
    snapshot_path: Path
    tf_path: Path | None = None

    def path(self, rel_path: str | os.PathLike[str]) -> Path:
        """*rel_path* resolved inside this repo. An absolute path is returned
        unchanged, so a caller that already holds one is not silently
        re-rooted."""
        candidate = Path(rel_path)
        return candidate if candidate.is_absolute() else self.root / candidate


def merged_snapshot_document() -> Mapping[str, Any]:
    """THE snapshot every built repo grounds against: the base agentic snapshot
    with the estate overlay's domain categories merged over it.

    Read through :func:`tests.agentic.env.merged_estate_document`, never
    re-derived here — one merge rule, in the frozen module that owns it.
    """
    return env.merged_estate_document()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, document: Any) -> Path:
    """The deterministic writer this module uses everywhere: sorted keys, two
    spaces, one trailing newline — so two builds of unchanged inputs, and a
    variant and its base, diff cleanly by construction."""
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def build_tf_repo(root: str | os.PathLike[str], *, snapshot: Any = None,
                  with_hcl: bool | None = None) -> TfRepo:
    """Copy the base corpus into *root* and return the built :class:`TfRepo`.

    The config template is copied to the dot-prefixed :data:`CONFIG_NAME` and
    every relative path inside it — the snapshot, the state file and each
    ``targets`` key — is rewritten to an absolute path under *root*, so a hook
    spawned with any working directory reads the same files.

    *snapshot* defaults to the merged agentic snapshot, WRITTEN INTO THE ROOT so
    a case module can vary it through :func:`variant` like any other file; pass
    an existing path to ground against that file instead and it is used where it
    lies.

    *with_hcl* defaults to :data:`HAVE_HCL_READER`: when the reader is part of
    the checkout an equivalent ``main.tf`` is written beside the ``.tf.json``,
    and when it is not there is nothing that could read one.

    Touches no network, spawns nothing, and returns in well under 50 ms.
    """
    # ABSOLUTE from here down, and normalised: every path this writes into the
    # config is read by a child process whose working directory is whatever the
    # agent's shell happened to be in.
    root_path = Path(os.path.abspath(os.fspath(root)))
    root_path.mkdir(parents=True, exist_ok=True)

    tf_json_path = root_path / TF_JSON_NAME
    state_path = root_path / STATE_NAME
    shutil.copyfile(BASE / TF_JSON_NAME, tf_json_path)
    shutil.copyfile(BASE / STATE_NAME, state_path)

    if snapshot is None:
        snapshot_path = _write_json(root_path / SNAPSHOT_NAME,
                                    merged_snapshot_document())
    else:
        snapshot_path = Path(os.path.abspath(os.fspath(snapshot)))

    config = _read_json(BASE / CONFIG_TEMPLATE)
    config["snapshot"] = str(snapshot_path)
    terraform = dict(config.get("terraform") or {})
    if "state" in terraform:
        terraform["state"] = str(root_path / terraform["state"])
    config["terraform"] = terraform
    config["targets"] = {str(root_path / key): value
                         for key, value in (config.get("targets") or {}).items()}
    config_path = _write_json(root_path / CONFIG_NAME, config)

    tf_path: Path | None = None
    write_hcl = HAVE_HCL_READER if with_hcl is None else bool(with_hcl)
    if write_hcl:
        tf_path = root_path / TF_NAME
        tf_path.write_text(render_hcl(_read_json(tf_json_path)), encoding="utf-8")

    return TfRepo(root=root_path, config_path=config_path, state_path=state_path,
                  tf_json_path=tf_json_path, snapshot_path=snapshot_path,
                  tf_path=tf_path)


def variant(repo: TfRepo, rel_path: str | os.PathLike[str],
            mutate: Callable[[Any], Any]) -> Path:
    """Apply *mutate* to the parsed JSON at *rel_path* and rewrite the file.

    THE ONLY WAY a case module derives an adversarial or benign edit: from a
    committed base rather than from a Python literal, so what the gate sees is
    always a reviewable document plus a named difference. *mutate* may return
    the new document or mutate the parsed one in place and return ``None``.

    Each case module still commits its OWN expected payload under its own
    fixture subdirectory — payload documents are reviewable files — and this is
    how the INPUT side stays reviewable too.
    """
    path = repo.path(rel_path)
    document = _read_json(path)
    changed = mutate(document)
    return _write_json(path, document if changed is None else changed)


def hook_argv(repo: TfRepo, *, extra: Iterable[str] = ()) -> tuple[str, ...]:
    """The shared state / config / clock argv every case passes to the hook
    runner, so all four case modules share ONE invocation shape and a flag
    change lands in one place.

    ``--snapshot`` is deliberately NOT here: it is the hook runner's own
    parameter, so a case passes ``snapshot=repo.snapshot_path`` to
    :func:`tests.agentic.hookrunner.run_hook` and this argv carries the rest.
    A ``--snapshot`` here would be the flag layer overriding the config file's
    own snapshot key, which is exactly the confusion one shape exists to avoid.
    """
    return (
        "--terraform-state", str(repo.state_path),
        "--config", str(repo.config_path),
        "--as-of", ASOF,
    ) + tuple(str(part) for part in extra)


def proposal_for(repo: TfRepo, case_id: str, rel_path: str, payload: Any,
                 expect: str, *, rationale: str = "") -> Proposal:
    """One scripted turn: a ``Write`` of *payload* to *rel_path*, expected to
    land in *expect*.

    Wraps the shared :class:`~tests.agentic.fake_agent.Proposal` with this
    document's two fixed choices — the ``Write`` tool and the ``tf_plan``
    proposal kind — so the case modules stay declarative. It validates nothing
    the proposal type already validates; ``expect`` and the tool name are
    checked there.
    """
    if os.path.isabs(rel_path):
        raise ValueError(
            f"proposal_for({case_id!r}): rel_path must be relative to the repo "
            f"root {str(repo.root)!r}, got the absolute path {rel_path!r} — the "
            f"fake agent resolves it against its workdir and an absolute path "
            f"would edit a file outside the repo under test")
    return Proposal(
        id=case_id, kind="tf_plan", tool_name="Write", rel_path=rel_path,
        payload=payload, expect=expect,
        rationale=rationale or (f"{case_id}: an agent rewrites {rel_path} in the "
                                f"terraform repo under review"))


# -- the equivalent HCL -------------------------------------------------------


def render_hcl(document: Mapping[str, Any]) -> str:
    """A ``.tf.json`` configuration document rendered as equivalent ``.tf``.

    Deliberately small, and it renders only what the base corpus contains:
    ``resource`` blocks whose bodies hold scalars, string lists and nested
    blocks. A list whose items are all mappings is a repeated BLOCK — which is
    what terraform's JSON syntax means by it — and anything else is a list
    literal.
    """
    lines: list[str] = []
    resources = document.get("resource") or {}
    for resource_type in sorted(resources):
        for name in sorted(resources[resource_type]):
            lines.append(f'resource "{resource_type}" "{name}" {{')
            lines.extend(_hcl_body(resources[resource_type][name], "  "))
            lines.append("}")
            lines.append("")
    return "\n".join(lines)


def _is_block_list(value: Any) -> bool:
    return (isinstance(value, list) and bool(value)
            and all(isinstance(item, Mapping) for item in value))


def _hcl_body(body: Mapping[str, Any], indent: str) -> list[str]:
    lines: list[str] = []
    for key in sorted(body):
        value = body[key]
        if _is_block_list(value):
            for item in value:
                lines.append(f"{indent}{key} {{")
                lines.extend(_hcl_body(item, indent + "  "))
                lines.append(f"{indent}}}")
        elif isinstance(value, Mapping):
            lines.append(f"{indent}{key} {{")
            lines.extend(_hcl_body(value, indent + "  "))
            lines.append(f"{indent}}}")
        else:
            lines.append(f"{indent}{key} = {json.dumps(value)}")
    return lines
