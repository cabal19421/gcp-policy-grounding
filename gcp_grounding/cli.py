"""Command-line interface: ``gcp-ground verify-policy`` / ``scan-command`` /
``compile-requirements``.

Three subcommands, exposed both as the ``gcp-ground`` console script and as
``python -m gcp_grounding``::

    gcp-ground verify-policy FILE [--snapshot PATH] [--baseline PATH]
                             [--format text|json] [--explain] [--hook]
                             [--bash-policy block|warn|off] [--abstain-notes]
                             [--requirements PATH]
                             [--origins PATH] [--merge-source PATH ...]
                             [--terraform-state PATH ...] [--terraform-plan PATH ...]
                             [--terraform-dir PATH ...] [--precedence SPEC]
                             [--drift-policy annotate|block|abstain]
                             [--max-age DURATION] [--completeness SCOPE]
                             [--as-of ISO8601] [--target DOMAIN:KEY ...]
                             [--no-auto-baseline] [--config PATH] [--no-config]
                             [--state-explain [DOMAIN:KEY]]
    gcp-ground scan-command --command STR|- [--format text|json]
    gcp-ground compile-requirements [DIR] [--snapshot PATH] [--out DIR]
                             [--check] [--format text|json]
                             [--no-independence] [--llm]

``verify-policy`` runs the preflight gate
(:func:`~gcp_grounding.preflight.ground_policy`) over one policy document;
``scan-command`` runs the offline shell classifier
(:func:`~gcp_grounding.bash_mutation.bash_mutation_verdicts`) over one command
line and prints the same ``gcp-grounding-report/1`` document. ``verify-policy``
deliberately does NOT grow a command-scanning mode: it grounds *documents*
against a snapshot, and overloading it would blur two surfaces that answer
different questions and have different exit-code contracts.

Exit codes carry the gate's honesty contract:

- ``0`` — the gate passed: every claim grounded *or* was honestly
  ``unverified`` (fail-open — ignorance never fails the gate);
- ``1`` — something is ungrounded or contradicted;
- ``2`` — a usage error in NORMAL mode (bad flags, no snapshot), or a real
  ungrounded/contradicted finding in ``--hook`` mode — ``2`` is the
  Claude-Code blocking exit code, and the findings go to stderr so the hook
  runner feeds them back to the agent. In hook mode there is no such thing as
  a usage error: an unusable invocation reports itself on stderr and exits 0,
  because a misconfigured hook must degrade to checking nothing, never to
  blocking everything.

``--snapshot`` falls back to the :data:`SNAPSHOT_ENV` environment variable —
a hook or CI job configures the estate snapshot once instead of per call.

THE THREE INPUTS
----------------

``verify-policy`` grounds a PROPOSAL against the CURRENT state under a set of
RULES:

- the PROPOSAL is ``FILE`` (or, in ``--hook`` mode, the edited file the
  PostToolUse event names);
- the CURRENT state is whatever the state flags below configure — additional
  estate snapshots, terraform state, terraform plan JSON and terraform
  configuration directories, reconciled by
  :func:`gcp_grounding.sources.load_current` into ONE view with a source
  ledger;
- the RULES are the built-in claim/document/pair checks plus the compiled
  requirements ``--requirements`` picks up, handed to
  :func:`gcp_grounding.engine.evaluate` as a
  :class:`~gcp_grounding.engine.RuleSet`. The engine loads no rules of its own,
  so building the rule set HERE is what keeps ``sec_requirements/`` reachable
  from both the CLI and the hook once a run routes through the engine.

**WITH NO STATE SOURCE CONFIGURED NOTHING CHANGES.** ``--snapshot`` alone is
the VOCABULARY, not a current-state source: a run that configures no state
source takes exactly the pre-existing path — ``ground_policy(FILE, snapshot,
baseline=..., rules=...)`` — and its stdout is byte-identical to what it has
always been, in both formats. The state machinery engages when, and only when,
one of ``--merge-source``, ``--terraform-state``, ``--terraform-plan``,
``--terraform-dir``, ``--origins``, ``--completeness`` or ``--target`` (or the
same settings from the environment or a config file) says the run has a current
state to reason about. That predicate also decides whether ``--format json``
grows its ``state`` key.

THE STATE FLAGS, all optional and all defaulting to today's behaviour:

============================== ================================================
``--origins PATH``             the primary snapshot's sidecar, when it does not
                               live beside it
``--merge-source PATH``        an additional estate snapshot (repeatable)
``--terraform-state PATH``     a terraform state file (repeatable)
``--terraform-plan PATH``      ``terraform show -json`` plan output (repeatable)
``--terraform-dir PATH``       a directory of terraform configuration (repeatable)
``--precedence SPEC``          a :func:`gcp_grounding.merge.parse_policy` spec:
                               a bare mode name or a mode plus
                               ``<category>=<mode>`` assignments
``--drift-policy MODE``        what a disagreement costs (default ``annotate``)
``--max-age DURATION``         the staleness ceiling (``7d``, ``36h``, ``off``)
``--completeness SCOPE``       the primary snapshot's coverage when it has NO
                               sidecar — the only way to license absence
                               reasoning over an estate table whose
                               ``.origins.json`` is missing
``--as-of ISO8601``            pin the clock (testing and CI reproducibility)
``--target DOMAIN:KEY``        which estate row this document is a proposal for
``--no-auto-baseline``         do not derive a current counterpart at all
``--config PATH`` ``--no-config`` name, or suppress, the config file
``--state-explain [DOMAIN:KEY]`` print the provenance block (or one target's
                               drill-down) to stderr
============================== ================================================

``--completeness`` is the explicit, auditable override and is deliberately NOT
an environment variable: a snapshot that travels without its sidecar is
``undeclared``, and licensing an absence must be something an operator said,
never something a shell inherited.

ENV FALLBACKS. Every variable :mod:`gcp_grounding.sources` documents is
honoured, read by that module's own :func:`~gcp_grounding.sources.from_env` in
its one legitimate role — ``resolve_settings``' ENVIRONMENT LAYER — rather than
by a second reader here: :data:`~gcp_grounding.sources.PRIMARY_ENV`
(the same name as :data:`SNAPSHOT_ENV`), ``ORIGINS_ENV``, ``MERGE_SOURCES_ENV``,
``TF_STATE_ENV``, ``TF_PLAN_ENV``, ``TF_DIR_ENV``, ``PRECEDENCE_ENV``,
``DRIFT_POLICY_ENV``, ``MAX_AGE_ENV``, ``NOW_ENV`` and ``SALT_ENV``, plus
:data:`gcp_grounding.discovery.CONFIG_ENV` for the config file and
:data:`REQUIREMENTS_ENV` for the rules. PRECEDENCE IS flags over environment
over config file over auto-detection over defaults, and it is implemented by
handing all four layers to :func:`gcp_grounding.discovery.resolve_settings`
rather than by or-chains here, so ``Settings.origins`` — what ``--state-explain``
prints — stays truthful about which layer supplied each value.

:func:`_load_snapshot` takes its options from
``discovery.to_source_options(discovery.resolve_settings(...))`` and NEVER from
``sources.SourceOptions.from_env``: ``from_env`` resolves the environment and
explicit overrides only, so building the primary through it would silently
bypass the config-file and auto-detect layers and ignore a snapshot path the
user wrote in a discovered config — with no error, no note, and a
successful-looking run against the wrong state.

A TFSTATE HANDED IN AS THE DOCUMENT IS NOT A PROPOSAL. ``verify-policy
estate.tfstate`` would otherwise route through
:func:`~gcp_grounding.preflight.detect_kind`, which reads a state file as a
plan (its key set carries ``terraform_version``), extract zero claims and print
a clean-looking pass over a file describing the whole estate. So
:func:`gcp_grounding.tfsource.discover.is_v4_state` — the same predicate the
capture gate uses, not a second sniff — runs BEFORE the detector, and on a hit
the document is not grounded at all: one verdict carrying
:data:`gcp_grounding.tfsource.discover.STATE_NOT_A_PROPOSAL`, exit 1 because the
run produced no grounding, and fail-open (exit 0, one stderr note) in ``--hook``
mode.

``--hook`` reads a Claude-Code PostToolUse event (JSON on stdin), pulls the
edited file out of ``tool_input.file_path``, and grounds it when it looks
like a policy document (``.tf``/``.json``, case-insensitive, matching the
gate's suffix rules). Everything else — unparsable
events, missing paths, non-policy files, an unavailable snapshot — exits 0:
a broken hook setup must never block an edit. A raw ``.tf`` file is not
``terraform show -json`` output, so no CLAIM is ever extracted from it and it
still contributes nothing but ``unverified`` verdicts of its own — but it no
longer follows that such a run is unjudged end to end: with a state source
configured the run still resolves settings, assembles the current state and
reports drift, and under ``--drift-policy block`` a material disagreement makes
the report not ok and the hook exits 2.

``--hook`` RESOLVES ITS SETTINGS PER EDITED FILE, rooting config discovery at
that file and walking up. That is what makes one fixed hook command line
correct for a repo with several terraform roots: one command, per-file state.
EVERY state problem in hook mode is fail-open — one prefixed stderr note and
exit 0 — and never a usage error, exactly as an unusable command line already
is. ``--baseline`` keeps working alongside it. Drift, staleness and provenance
notes are all ``unverified``, so they are INVISIBLE in hook mode unless
``--abstain-notes`` is on; that is deliberate, because the hook's default
contract is silence on a passing run. ``--drift-policy block`` is how material
drift is made to block: it turns the material drift verdict into a
``contradicted``, so the report is not ok and the hook exits 2.

``--hook`` also inspects ``tool_input.command`` — the largest bypass around a
file-based guardrail is to stop writing files and run ``gcloud`` instead. The
command is matched against a curated list of state-mutating ``gcloud``,
``terraform``, ``gsutil``, ``bq``, ``kubectl`` and ``curl`` shapes: a known
mutator BLOCKS by default (:data:`BASH_POLICY_ENV` / ``--bash-policy`` relax it
to ``warn`` or ``off``), while an unknown ``gcloud`` verb abstains with the verb
quoted, exactly as it does in :mod:`~gcp_grounding.bash_mutation`. That block is
a POLICY decision and is deliberately kept separate from ``report.ok``: every
bash verdict is ``unverified``, so no shell command is ever recorded as
``ungrounded`` or ``contradicted`` — the gate did not refute it, it was unable
to look. The same verdicts are printed by ``scan-command``, which is how a
bypass attempt reaches a machine-readable record instead of only stderr.

The hook is SCOPED, and the scope is the contract: it grounds events from
any tool EXCEPT a curated read-only set (:data:`_READ_ONLY_TOOLS`), and it
declines ``PreToolUse`` file events with an explanation on stderr instead of
judging them. Two decisions, each with a reason.

*Reading a policy is not changing one.* A ``Read`` of a bad policy used to
exit 2, which blocks on a file the agent did not write; a guardrail that
fires on inspection is the classic reason operators switch guardrails off.
The exit-2 stderr is fed back to the agent as if it had just made that
error, corrupting the block-then-retry loop; and it is trivially
self-inflicted, since an agent asked to AUDIT policies cannot read them. The
obvious counter-argument — that scoping opens a bypass — is answered by the
*shape* of the fix: :data:`_READ_ONLY_TOOLS` is a DENY-list of read-only
tools, never an ALLOW-list of mutators. An unknown ``tool_name``, an absent
one, and every ``mcp__*`` tool all stay INSIDE the gate, so the change
removes a false-positive class and cannot remove coverage.

*A PreToolUse file event cannot be judged honestly.* ``ground_policy`` reads
the file FROM DISK, and on ``PreToolUse`` the edit has not landed, so disk
still holds the OLD content: grounding it would produce a verdict about the
wrong document — a WRONG verdict, not merely a useless one. Abstaining out
loud is the only honest option, and the stderr line names the path and tells
the operator to register the hook on ``PostToolUse`` instead. ``PreToolUse``
for a BASH command is the opposite case: there the mutation genuinely has
not happened yet, which is precisely when you want to intervene, and it is
handled by the bash arm, which runs before this check — a Bash event carries
a ``command``, never a ``tool_input.file_path``, so this check returns
"proceed" for it either way.

``--hook`` has an ABSTAIN CHANNEL, opt-in via ``--abstain-notes`` /
:data:`ABSTAIN_NOTES_ENV`. Without it, a hook run that could not judge the
document is completely silent — zero stdout, zero stderr, exit 0 — which is
byte-for-byte what a clean pass looks like, so a raw ``.tf`` file, an
unparsable policy, a CEL condition z3 was not there to decide, a missing
``tf_claims``, an uncaptured snapshot category and a tautology warning all
reach the agent as an unqualified success. With it, every ``unverified``
verdict is printed to stderr under a ``NOT DECIDED`` header, rendered exactly
as the human report renders its unverified lines, and the ignorance is on the
record while the exit code stays 0. This channel NEVER blocks and never
changes an exit code; it is opt-in because the hook's stderr is agent-visible
and the default contract is silence on a passing run.

The eventual replacement is structured JSON on stdout — a
``hookSpecificOutput`` object with an ``additionalContext`` field, which
Claude Code feeds to the agent without blocking, so the ignorance would reach
the agent as data rather than as prose on stderr. That option needs stdout,
and the stdout-is-empty invariant of hook mode is preserved here deliberately
— the notes go to stderr alone — so it stays available.

``compile-requirements`` runs stage 1 of the requirements compiler
(:func:`gcp_grounding.sec_compile.compile_directory`) over a directory of
markdown requirements, writing one reviewable ``*.promises.json`` per document
into ``--out`` (default ``<DIR>/compiled``). Its exit codes are the gate's,
read over the compile:

- ``0`` — every promise compiled, or was honestly ``unverified``;
- ``1`` — a promise was ``rejected``, or ``--check`` found artifact drift;
- ``2`` — a usage error, including a missing or unreadable ``--snapshot``.

The snapshot is REQUIRED here, unlike in hook mode: compiling without one
cannot ground a requirement's vocabulary, so a promise naming a hallucinated
role would compile clean. Refusing to start is the only honest option. ``--llm``
is optional in the strongest sense — when :mod:`gcp_grounding.sec_llm` is absent
it prints one stderr note and compiles deterministically rather than failing.

``verify-policy --requirements PATH`` picks the compiled artifacts back up: a
directory of ``*.promises.json`` or a single one, falling back to
:data:`REQUIREMENTS_ENV`, which is how a hook or CI job turns requirements on
globally. With neither set, no rules load and nothing extra is printed — the
report only ever claims what it checked, so silence is honest.

A NON-ENFORCING REQUIREMENT GETS ITS OWN STARTUP LINE, and it does NOT depend
on ``--abstain-notes``. A user-authored promise that fails to compile would
otherwise be invisible in the mode operators actually run:
:mod:`~gcp_grounding.sec_rules` maps a ``rejected`` promise to an ``unverified``
carry verdict, so ``report.ok`` stays True, and the abstain channel defaults
off — a typo'd requirement would yield exit 0 with byte-empty stderr and zero
enforcement, indistinguishable from the rule working. So whenever a requirements
source resolves and any loaded promise is not enforcing, ONE line goes to stderr
on every run, in both hook and normal mode, naming the artifact directory. The
exit code is unchanged in every case: this is a notice, never a block, so it
cannot resurrect the fail-closed hole ``--hook``'s fail-open contract closed.
When every loaded promise is enforcing, nothing is printed — a channel that
fires on a healthy configuration is noise, and noise gets guardrails switched
off.

``--explain`` re-derives and dumps (to stderr, keeping stdout parseable for
``--format json``) the z3 constraints this run generated: the translated
formula per ``cel`` condition and the new⊈old satisfiability assertion when
a ``--baseline`` comparison ran. The derivation is deterministic, so the
re-generated formulas are exactly the ones the checks decided. With requirements
configured it also prints each compiled promise's s-expression and its two
pinned witnesses (:func:`gcp_grounding.sec_evidence.explain_lines`).

``--format json`` emits :func:`gcp_grounding.sec_evidence.sec_document` instead
of :meth:`~gcp_grounding.report.PolicyReport.to_dict` whenever a requirements
source was CONFIGURED — even if it resolved to zero rules — so a consumer that
turned requirements on always sees the same shape and can tell "no rules loaded"
(``sec.requirements == []``) from "requirements are off" (no ``sec`` key at
all). The gate is CONFIGURATION, not load outcome; keying it on whether rules
happened to load would make the document shape depend on whether a compile
succeeded. With no requirements source configured the output is byte-identical
to what it has always been.

``--state-explain`` prints :func:`gcp_grounding.explain_state.state_lines` — the
sources, the settings and where each came from, the per-target baseline outcomes
and the drift — to STDERR, keeping stdout parseable under ``--format json``.
With an argument it prints that one target's drill-down
(:func:`~gcp_grounding.explain_state.fact_lines`) instead. It works in both
modes, and ``--explain`` appends the same lines after its solver block and after
the compiled-requirements block.

``--format json`` grows a top-level ``state`` key holding
:func:`gcp_grounding.explain_state.state_document` under exactly the same
discipline the ``sec`` key uses: it appears whenever a state source was
CONFIGURED, even when every one of them failed to load (its ``sources`` list is
then empty), so a consumer can tell sources-configured-but-none-loaded from
state-is-off. With nothing configured the document is byte-identical to today's.

ONE OPERATOR NOTICE, on every run in both modes, when a state source was
configured and any of them contributed nothing while the derivation was left
with an unqueried baseline or a failed source: a single prefixed line naming how
many configured sources contributed nothing and saying the current-state
comparison was incomplete. Like the not-enforcing notice above it is NOT gated
on ``--abstain-notes`` — a silently inert baseline is indistinguishable from a
passing one — and it NEVER changes an exit code. Nothing is printed when every
configured source loaded.

stdlib ``argparse`` only — no third-party CLI framework.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib
import importlib.util
import inspect
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Mapping

from . import discovery, drift, engine, explain_state, freshness, merge, provenance, redact, sources
# Imported by NAME rather than as the module, because ``baseline`` is also the
# name of a CLI flag and of more than one local here — a shadowed module is a
# NameError waiting for the one branch nobody exercised.
from .baseline import Hints, TargetRef
from .claims import iam_policy_claims, org_policy_claims
# Explain reuses the constraint layer's own encoders (private to the package,
# not the world) — re-implementing the CEL translation here would let the
# dumped formulas drift from the ones actually decided.
from .constraints import (
    check_policy_subset,
    UnsupportedCel,
    _CelToZ3,
    _condition_formula,
    _grant_pairs,
    _Undecidable,
    _z3_module,
)
from .core.log import get_logger
from .core.report import GroundingReport, Verdict
from .core.solver import get_solver
from .knowledge import GcpSnapshot
from .preflight import detect_kind, ground_policy
# _MARKS / _STAMPED are the human render's own presentation rules: the abstain
# channel reuses them so its lines cannot drift from the unverified lines of the
# report a blocking run prints.
from .report import _MARKS, _STAMPED, PolicyReport

logger = get_logger(__name__)

__all__ = ["ABSTAIN_NOTES_ENV", "BASH_POLICY_ENV", "REQUIREMENTS_ENV",
           "SNAPSHOT_ENV", "build_parser", "main"]

#: Environment variable consulted when ``--snapshot`` is not given.
SNAPSHOT_ENV = "GCP_GROUNDING_SNAPSHOT"

#: Environment variable consulted when ``--bash-policy`` is not given.
BASH_POLICY_ENV = "GCP_GROUNDING_BASH_POLICY"

#: Environment variable that turns the ``--hook`` abstain channel on when
#: ``--abstain-notes`` is not given — one export configures a whole session's
#: hooks, exactly as :data:`SNAPSHOT_ENV` does.
ABSTAIN_NOTES_ENV = "GCP_GROUNDING_ABSTAIN_NOTES"

#: Environment variable naming the compiled requirements — an artifact
#: directory or a single ``*.promises.json`` — when ``--requirements`` is not
#: given. Exporting it once is how a hook or a CI job turns requirements on
#: globally, exactly as :data:`SNAPSHOT_ENV` configures the estate.
REQUIREMENTS_ENV = "GCP_GROUNDING_REQUIREMENTS"

#: Where ``compile-requirements`` looks when DIR is omitted, resolved against
#: the cwd.
_DEFAULT_REQUIREMENTS_DIR = "sec_requirements"

#: The ``--completeness`` choices: every scope an operator can DECLARE.
#: ``uncaptured`` is excluded because it is what a category nobody captured
#: already is, not something a snapshot in hand can be declared to be.
_COMPLETENESS = tuple(scope for scope in provenance.SCOPES if scope != "uncaptured")

#: The settings whose presence means this run has a CURRENT STATE to reason
#: about. ``primary`` is deliberately NOT among them: ``--snapshot`` alone is
#: the vocabulary and has always been, so a run that names only a snapshot takes
#: the pre-existing path and its output stays byte-identical. See
#: :func:`_state_configured`.
_STATE_OPTIONS = ("extra", "terraform_state", "terraform_plan", "terraform_dir",
                  "origins", "completeness")

#: The verdict kinds :func:`gcp_grounding.sources.load_current` gives a
#: configured source that contributed NOTHING — the incomplete-coverage signal
#: :func:`_incomplete_notice` fires on. Read from the module that defines them
#: so a renamed kind cannot leave that channel silently inert. (The other
#: incomplete-coverage kind, ``baseline:unqueried``, is deliberately not here;
#: see :func:`_incomplete_notice`.)
_SOURCE_FAILED_KINDS = frozenset(k for k in sources.PROVENANCE_KINDS
                                 if k != "provenance")

#: The kind of the one verdict a terraform STATE file handed in as the document
#: earns. A new kind, not a new status: kinds are in neither ``report.SCHEMA``
#: nor ``gate.GATE_SCHEMA``.
_STATE_DOCUMENT_KIND = "state:not-a-proposal"

#: Environment values that mean "on", case-insensitively, mirroring the
#: harness's truthy set. ANYTHING else is False — including ``"off"``,
#: ``"0"``, the empty string and a typo — because the channel is opt-in and an
#: unrecognized value must not opt an operator in behind their back.
_TRUTHY_ENV = frozenset({"1", "true", "yes", "on"})

#: How ``--hook`` treats a state-mutating shell command: ``block`` exits 2,
#: ``warn`` reports it and exits 0, ``off`` does not scan at all.
_BASH_POLICIES = ("block", "warn", "off")

#: Fail-closed by default: an unscanned ``gcloud`` mutation is the bypass this
#: arm exists to close, so silence is not an option the default may pick.
_DEFAULT_BASH_POLICY = "block"

#: The :mod:`~gcp_grounding.bash_mutation` verdict kind that a ``block`` policy
#: acts on; ``bash-unrecognized`` findings are reported and NEVER block.
_BASH_MUTATION_KIND = "bash-mutation"

#: :class:`~gcp_grounding.report.PolicyReport` requires a freshness stamp, and a
#: shell scan genuinely consults no snapshot — it reads the command text alone.
#: Saying so is the honest stamp; an ISO timestamp here would imply the estate
#: was looked at.
_BASH_CAPTURED_AT = "not consulted"

#: No constraint solver participates in a shell scan: the classifier is a pure
#: text pass, so the report names no backend rather than the one z3 that
#: happened to be importable.
_BASH_BACKEND = "none"

#: The mark and the freshness stamping rule the human render gives an
#: ``unverified`` line (report.py's ``_MARKS`` / ``_STAMPED``), read once here
#: so the abstain channel reads identically to the report's own lines.
_ABSTAIN_MARK = dict(_MARKS)["unverified"]
_ABSTAIN_STAMPED = "unverified" in _STAMPED

#: CLI ``--format`` values → :meth:`PolicyReport.render` formats.
_FORMATS = {"text": "human", "json": "json"}

#: File suffixes ``--hook`` treats as policy documents worth grounding.
_HOOK_SUFFIXES = (".tf", ".json")

#: Tools whose events ``--hook`` refuses to ground, because they change
#: nothing: reading a policy is not proposing one.
#:
#: A DENY-list, deliberately — NOT an allow-list of mutating tools. An unknown
#: ``tool_name`` (a new MCP writer, a tool this release has never heard of) is
#: not on it, so it stays INSIDE the gate. That asymmetry is what makes the
#: scoping safe: it can only ever remove false positives, never open a bypass.
_READ_ONLY_TOOLS = frozenset({
    "Read",
    "NotebookRead",
    "Glob",
    "Grep",
    "LS",
    "WebFetch",
    "WebSearch",
    "Task",
    "TodoWrite",
    "BashOutput",
    "KillShell",
    "ExitPlanMode",
    "SlashCommand",
    "AskUserQuestion",
})

EXIT_OK = 0
EXIT_FAILED = 1
#: Usage errors, and hook-mode gate failures (Claude Code's blocking code).
EXIT_BLOCK = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gcp-ground",
        description="Ground GCP IAM / Org Policy documents against a frozen "
                    "estate snapshot — hallucinated names fail, honest "
                    "ignorance does not.")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser(
        "verify-policy",
        help="ground one policy document; exit 1 iff something is "
             "ungrounded/contradicted",
        description="Ground FILE (IAM policy / Org Policy / terraform plan "
                    "JSON, auto-detected) against the snapshot.")
    verify.add_argument(
        "file", nargs="?", metavar="FILE",
        help="policy document to ground (omitted in --hook mode, where the "
             "edited file comes from the PostToolUse event)")
    verify.add_argument(
        "--snapshot", metavar="PATH",
        help=f"estate snapshot JSON (default: ${SNAPSHOT_ENV})")
    verify.add_argument(
        "--baseline", metavar="PATH",
        help="baseline IAM policy — opts into the z3 new⊆old comparison")
    verify.add_argument(
        "--format", choices=tuple(_FORMATS), default="text",
        help="report format on stdout (default: text)")
    verify.add_argument(
        "--explain", action="store_true",
        help="dump the z3 constraints generated this run to stderr")
    verify.add_argument(
        "--hook", action="store_true",
        help="read a Claude-Code PostToolUse event JSON on stdin and ground "
             "the edited .tf/policy file; findings block via exit 2 + stderr")
    verify.add_argument(
        "--bash-policy", choices=_BASH_POLICIES, default=None,
        help=f"how --hook treats a state-mutating gcloud/terraform command "
             f"(default: {_DEFAULT_BASH_POLICY}, falling back to "
             f"${BASH_POLICY_ENV}); block exits 2, warn reports and exits 0, "
             f"off skips the scan")
    verify.add_argument(
        "--abstain-notes", action="store_true", default=False,
        help=f"in --hook mode, print the verdicts the gate could not judge "
             f"(the 'unverified' bucket) to stderr and still exit 0 — this "
             f"NEVER blocks anything (default: off, honouring "
             f"${ABSTAIN_NOTES_ENV}=1|true|yes|on)")
    verify.add_argument(
        "--requirements", metavar="PATH",
        help=f"compiled requirements to run alongside the built-in checks: a "
             f"directory of *.promises.json or a single one (default: "
             f"${REQUIREMENTS_ENV}; unset means no rules load)")
    _add_state_flags(verify)
    verify.set_defaults(handler=_cmd_verify_policy)
    scan = sub.add_parser(
        "scan-command",
        help="classify one shell command for state-mutating GCP CLI "
             "invocations; always exit 0",
        description="Run the offline bash-mutation classifier over COMMAND and "
                    "print the same gcp-grounding-report/1 document the hook "
                    "renders. Exit 0 always: every finding is 'unverified', so "
                    "the report stays ok — the BLOCK decision belongs to the "
                    "hook's --bash-policy and to nothing else.")
    scan.add_argument(
        "--command", metavar="STR", required=True,
        help="the shell command to classify ('-' reads it from stdin)")
    scan.add_argument(
        "--format", choices=tuple(_FORMATS), default="text",
        help="report format on stdout (default: text)")
    scan.set_defaults(handler=_cmd_scan_command)
    compile_req = sub.add_parser(
        "compile-requirements",
        help="compile a directory of markdown requirements into reviewable "
             "*.promises.json artifacts; exit 1 iff a promise was rejected or "
             "an artifact drifted",
        description="Run stage 1 of the requirements compiler over DIR, "
                    "grounding every requirement's vocabulary against the "
                    "snapshot and writing one artifact per document. A "
                    "snapshot is REQUIRED: without one a requirement naming a "
                    "hallucinated role would compile clean, and pretending to "
                    "have checked is the one thing this gate does not do.")
    compile_req.add_argument(
        "directory", nargs="?", metavar="DIR", default=_DEFAULT_REQUIREMENTS_DIR,
        help=f"directory of *.md requirement documents, resolved against the "
             f"cwd (default: {_DEFAULT_REQUIREMENTS_DIR})")
    compile_req.add_argument(
        "--snapshot", metavar="PATH",
        help=f"estate snapshot JSON (default: ${SNAPSHOT_ENV}); missing or "
             f"unreadable is a usage error, not a fail-open")
    compile_req.add_argument(
        "--out", metavar="DIR", default=None,
        help="where the artifacts are written (default: <DIR>/compiled)")
    compile_req.add_argument(
        "--check", action="store_true",
        help="compile in memory and fail on artifact drift instead of writing "
             "— the CI mode that keeps committed artifacts honest")
    compile_req.add_argument(
        "--format", choices=tuple(_FORMATS), default="text",
        help="report format on stdout (default: text)")
    compile_req.add_argument(
        "--no-independence", action="store_true",
        help="skip the compile-time independence probe between promises")
    compile_req.add_argument(
        "--llm", action="store_true",
        help="use the LLM-assisted stage when gcp_grounding.sec_llm is "
             "available; otherwise note it on stderr and compile "
             "deterministically (never a hard failure)")
    compile_req.set_defaults(handler=_cmd_compile_requirements)
    return parser


def _add_state_flags(verify: argparse.ArgumentParser) -> None:
    """THE ONE state-flag set — the second input, on ``verify-policy``.

    Every flag is optional and every default is today's behaviour, which is what
    makes the no-flag invocation byte-identical. ``--snapshot`` stays
    single-valued: a repeatable primary would be a second way to spell
    ``--merge-source``, and the shape is pinned by a frozen test module.
    """
    verify.add_argument(
        "--origins", metavar="PATH",
        help=f"the --snapshot sidecar (its coverage ledger) when it does not "
             f"live beside the snapshot (default: ${sources.ORIGINS_ENV})")
    verify.add_argument(
        "--merge-source", metavar="PATH", action="append", default=None,
        help=f"an additional estate snapshot to reconcile with --snapshot "
             f"(repeatable; default: ${sources.MERGE_SOURCES_ENV}, "
             f"{os.pathsep!r}-separated)")
    verify.add_argument(
        "--terraform-state", metavar="PATH", action="append", default=None,
        help=f"a terraform state file to read as a current-state source "
             f"(repeatable; default: ${sources.TF_STATE_ENV})")
    verify.add_argument(
        "--terraform-plan", metavar="PATH", action="append", default=None,
        help=f"`terraform show -json` plan output, read for its PRIOR state "
             f"(repeatable; default: ${sources.TF_PLAN_ENV})")
    verify.add_argument(
        "--terraform-dir", metavar="PATH", action="append", default=None,
        help=f"a directory of terraform configuration (.tf/.tf.json) to read as "
             f"a current-state source (repeatable; default: "
             f"${sources.TF_DIR_ENV})")
    verify.add_argument(
        "--precedence", metavar="SPEC", default=None,
        help=f"which source wins where two disagree: a bare mode "
             f"({'/'.join(merge.PRECEDENCE)}) or a mode plus "
             f"'<category>=<mode>' assignments, comma- or space-separated "
             f"(default: {merge.DEFAULT_PRECEDENCE}, falling back to "
             f"${sources.PRECEDENCE_ENV}). THE LOSING VALUE IS REPORTED "
             f"WHATEVER WINS: precedence decides which document is primary, "
             f"never which finding is true")
    verify.add_argument(
        "--drift-policy", choices=drift.DRIFT_POLICIES, default=None,
        help=f"what a disagreement between sources costs: 'annotate' reports "
             f"every drift and never blocks; 'block' turns a material "
             f"disagreement into a gate failure (exit 1, or 2 in --hook mode); "
             f"'abstain' additionally downgrades a finding whose evidence is "
             f"itself disputed (default: {drift.DEFAULT_DRIFT_POLICY}, falling "
             f"back to ${sources.DRIFT_POLICY_ENV})")
    verify.add_argument(
        "--max-age", metavar="DURATION", default=None,
        help=f"how old a source may be before its facts stop justifying a pass "
             f"— '7d', '36h', a bare integer of seconds, or 'off' for no limit "
             f"(default: {int(freshness.MAX_AGE_DEFAULT.total_seconds()) // 86400}d, "
             f"falling back to ${sources.MAX_AGE_ENV})")
    verify.add_argument(
        "--completeness", choices=_COMPLETENESS, default=None,
        help="the --snapshot's coverage when it has NO .origins.json sidecar. "
             "THE ONLY WAY to license absence reasoning for an estate table "
             "whose sidecar is missing: a snapshot that travels without its "
             "sidecar is 'undeclared', and this flag is the explicit, auditable "
             "override rather than an accident (default: unset, so the "
             "shape-based fallback in sources.load_source applies)")
    verify.add_argument(
        "--as-of", metavar="ISO8601", default=None,
        help=f"pin the clock every staleness answer is measured against, as an "
             f"AWARE ISO-8601 instant — a testing and CI-reproducibility aid, "
             f"so an age assertion cannot drift with the wall clock (default: "
             f"${sources.NOW_ENV}, else now)")
    verify.add_argument(
        "--target", metavar="DOMAIN:KEY", action="append", default=None,
        help=f"which estate row this document proposes to change, when the "
             f"document does not name it (an IAM allow policy never does): one "
             f"of the estate domains {list(provenance.CATEGORIES)} and that "
             f"row's canonical key. NO domain is ever guessed from the key. "
             f"Repeatable; the last one wins for this document, and the "
             f"per-path map form lives in the config file")
    verify.add_argument(
        "--no-auto-baseline", action="store_true",
        help="do not derive a current counterpart for the changed rows at all; "
             "every pair check then abstains with a stated reason")
    verify.add_argument(
        "--config", metavar="PATH", default=None,
        help=f"the config file to read, instead of walking up from the document "
             f"(default: ${discovery.CONFIG_ENV}, else the first "
             f"{discovery.CONFIG_NAMES[0]} found walking up)")
    verify.add_argument(
        "--no-config", action="store_true",
        help="do not look for a config file and do not auto-detect a sibling "
             "terraform state; the flags and the environment are the whole "
             "configuration")
    verify.add_argument(
        "--state-explain", metavar="DOMAIN:KEY", nargs="?", const="", default=None,
        help="print to stderr which current-state sources were read, how old "
             "they are, where every setting came from and what each changed row "
             "was compared against; with a DOMAIN:KEY argument, print that one "
             "row's full drill-down instead")


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    try:
        args = build_parser().parse_args(raw)
    except SystemExit:
        # argparse has already failed and exited, so there is no namespace to
        # consult (no ``args.hook``) — the raw argv is all we have left. If it
        # carries the literal ``--hook``, degrade to checking nothing (stderr +
        # exit 0), because a misconfigured hook must fail open, never block
        # every edit with a SystemExit(2). ``--help`` also exits 0 here, which
        # is correct: argparse already printed the help text. Normal mode
        # re-raises, keeping the usage-error exit 2.
        if "--hook" in raw:
            print("gcp-ground --hook: the hook command line is not usable — "
                  "nothing was checked (fail-open)", file=sys.stderr)
            return EXIT_OK
        raise
    return args.handler(args)


# -- verify-policy ------------------------------------------------------------


def _cmd_verify_policy(args: argparse.Namespace) -> int:
    if args.hook:
        if args.file is not None:
            return _usage("FILE and --hook are mutually exclusive — the hook "
                          "event names the edited file", hook=True)
        return _run_hook(args)
    if args.bash_policy is not None:
        # Accepted and ignored, never a usage error: one wrapper script tends to
        # invoke the gate both ways, and failing the normal-mode call over a
        # flag that is merely irrelevant there would be gratuitous.
        logger.debug("--bash-policy=%r is ignored outside --hook mode",
                     args.bash_policy)
    if args.file is None:
        return _usage("FILE is required (only --hook mode reads the file from "
                      "a PostToolUse event instead)")
    # NORMAL MODE ONLY: a malformed state flag is a usage error naming the
    # token, never a silent fall back to the default — a typo that quietly
    # restored the default would change what the gate enforces with nothing
    # saying so.
    problem = _state_flag_problem(args)
    if problem is not None:
        return _usage(problem)
    settings, notes = _resolve_settings(args, start=args.file)
    snapshot, more, problem = _load_snapshot(args, settings=settings)
    if snapshot is None:
        return _usage(problem)
    notes += more
    refusal = _not_a_proposal(args.file)
    if refusal is not None:
        # NOT GROUNDED AT ALL. Grading a state file would report the whole
        # estate as if an agent had just written it; exit 1 because the run
        # produced no grounding, which is not a pass.
        report = GroundingReport()
        report.backend = get_solver().backend
        report.add(refusal)
        _finish_report(report, snapshot, notes)
        print(PolicyReport(report, captured_at=snapshot.captured_at,
                           source=args.file).render(_FORMATS[args.format]))
        return EXIT_FAILED
    source = _requirements_source(args, settings)
    rules, carried = _load_requirements(source, hook=False)
    ground = _ground(args, settings, snapshot, notes, path=args.file,
                     rules=rules, carried=carried)
    if ground.problem is not None:
        return _usage(ground.problem)
    # THE HEADER'S captured-at STAYS THE SNAPSHOT'S. It is pinned by frozen
    # tests, and the per-source capture times live in the provenance block
    # (--state-explain) where several ages can be told apart, which one header
    # stamp structurally cannot do.
    policy_report = PolicyReport(ground.report, captured_at=snapshot.captured_at,
                                 source=args.file)
    # The state document is BUILT only where it is rendered: it is the json
    # format's key, and the human render carries the same content through
    # --state-explain.
    state = _state_document(ground, settings) if args.format == "json" else None
    print(_render_policy(policy_report, args.format, source, rules, state=state))
    if args.explain:
        lines = _explain_lines(args.file, args.baseline)
        lines.extend(_sec_explain_lines(source, rules))
        lines.extend(_state_explain_lines(ground, settings, ""))
        print("\n".join(lines), file=sys.stderr)
    if args.state_explain is not None:
        print("\n".join(_state_explain_lines(ground, settings, args.state_explain)),
              file=sys.stderr)
    _incomplete_notice(ground, settings, hook=False)
    return EXIT_OK if ground.report.ok else EXIT_FAILED


def _usage(problem: str, *, hook: bool = False,
           prog: str = "verify-policy") -> int:
    if hook:
        # Reuse the fail-open wording so operators see one phrase across the
        # stdin, snapshot and argv arms — a hook usage error checks nothing and
        # exits 0, never blocking the edit (see the exit-code docstring above).
        print(f"gcp-ground --hook: {problem} — nothing was checked (fail-open)",
              file=sys.stderr)
        return EXIT_OK
    print(f"gcp-ground {prog}: error: {problem}", file=sys.stderr)
    return EXIT_BLOCK


def _load_snapshot(args: argparse.Namespace, *,
                   settings: discovery.Settings | None = None,
                   start: str = "") -> tuple[GcpSnapshot | None,
                                             tuple[Verdict, ...], str | None]:
    """→ (snapshot, notes, problem) — exactly one of snapshot/problem is
    meaningful; never raises.

    THE PRIMARY COMES FROM ``discovery.to_source_options(resolve_settings(...))``
    AND NEVER FROM ``sources.SourceOptions.from_env``, and the distinction is the
    whole point: ``from_env`` resolves the environment and explicit overrides
    ONLY, so building the primary through it silently bypasses the config-file
    and auto-detect layers this command promises — a snapshot path the user
    wrote in a discovered config file would be ignored with no error, no note
    and a successful-looking run against the wrong state. ``from_env`` is the
    library and no-CLI path; this is not it.

    *settings* is the already-resolved four-layer answer when the caller has one
    (``verify-policy`` resolves it once and reuses it); otherwise they are
    resolved here from *start*, and the discovery problems come back as the
    notes.
    """
    notes: tuple[Verdict, ...] = ()
    if settings is None:
        settings, notes = _resolve_settings(args, start=start)
    options = discovery.to_source_options(settings, as_of=None)
    path = options.primary
    if not path:
        return None, notes, (f"an estate snapshot is required: pass --snapshot "
                             f"PATH or set ${SNAPSHOT_ENV}")
    try:
        return GcpSnapshot.load(path), notes, None
    except OSError as exc:
        return None, notes, f"snapshot {path}: could not be read ({exc})"
    except ValueError as exc:
        return None, notes, str(exc)  # GcpSnapshot.load already names the path


# -- the second input: settings, current state, and the three-input engine -----


@dataclass(frozen=True)
class _Ground:
    """One grounding pass, plus everything the surfaces around it need.

    ``current`` and ``result`` are ``None`` on the no-state path, where nothing
    was assembled and there is nothing to explain — which is exactly what
    :func:`gcp_grounding.explain_state.state_lines` renders as "none
    configured".
    """

    report: GroundingReport
    current: Any = None
    result: Any = None
    problem: str | None = None


def _state_configured(settings: discovery.Settings) -> bool:
    """Whether this run has a CURRENT STATE to reason about.

    ``primary`` is deliberately not counted: ``--snapshot`` alone has always
    been the VOCABULARY, and a run that names only a snapshot must keep taking
    the pre-existing path so its output stays byte-identical. Everything in
    :data:`_STATE_OPTIONS` — and a target, which is a statement about which
    estate row the document changes — says the operator asked for current-state
    work, whichever layer said it.
    """
    options = settings.options
    return bool(settings.targets
                or any(getattr(options, name, None) for name in _STATE_OPTIONS))


def _parse_target(raw: str) -> tuple[TargetRef | None, str | None]:
    """``DOMAIN:KEY`` as a :class:`~gcp_grounding.baseline.TargetRef`.

    NO DOMAIN IS GUESSED from the key and no key from the path: a near-miss
    target silently redefines what the widening check compares against, which is
    worse than having no target at all.
    """
    domain, sep, key = str(raw).partition(":")
    domain, key = domain.strip(), key.strip()
    if not sep or not domain or not key:
        return None, (f"--target {raw!r} is not a '<domain>:<key>' pair; the "
                      f"domain is one of {list(provenance.CATEGORIES)} and NO "
                      f"domain is guessed from the key")
    if domain not in provenance.CATEGORIES:
        return None, (f"--target {raw!r} names domain {domain!r}, which is not "
                      f"an estate category; expected one of "
                      f"{list(provenance.CATEGORIES)}")
    try:
        return TargetRef(category=domain, key=key, how="explicit-flag"), None
    except ValueError as exc:
        return None, f"--target {raw!r}: {exc}"


def _state_flag_problem(args: argparse.Namespace) -> str | None:
    """The first malformed state flag, named with its token — or ``None``.

    NORMAL MODE ONLY. In hook mode every one of these is fail-open: see
    :func:`_run_hook`.
    """
    precedence = getattr(args, "precedence", None)
    if precedence:
        try:
            merge.parse_policy(precedence)
        except ValueError as exc:
            return f"--precedence {precedence!r}: {exc}"
    max_age = getattr(args, "max_age", None)
    if max_age is not None:
        try:
            freshness.parse_duration(max_age)
        except ValueError as exc:
            return f"--max-age {max_age!r}: {exc}"
    as_of = getattr(args, "as_of", None)
    if as_of is not None:
        try:
            freshness.resolve_now(as_of)
        except ValueError as exc:
            return f"--as-of {as_of!r}: {exc}"
    for raw in getattr(args, "target", None) or ():
        _ref, problem = _parse_target(raw)
        if problem is not None:
            return problem
    return None


def _cli_layer(args: argparse.Namespace, start: str) -> dict[str, Any]:
    """THE FLAG LAYER, keyed by :data:`gcp_grounding.discovery.SETTINGS_FIELDS`.

    Only flags the user actually gave appear: an absent key is what lets the
    environment, then the config file, then auto-detection, then the defaults
    answer. Nothing is or-chained here — the layering is
    :func:`gcp_grounding.discovery.resolve_settings`' job, and doing it twice is
    how ``Settings.origins`` starts lying about where a value came from.
    """
    layer: dict[str, Any] = {}
    for flag, field in (("snapshot", "primary"), ("origins", "origins"),
                        ("precedence", "precedence"),
                        ("drift_policy", "drift_policy"), ("max_age", "max_age"),
                        ("as_of", "now"), ("completeness", "completeness")):
        value = getattr(args, flag, None)
        if value:
            layer[field] = value
    for flag, field in (("merge_source", "extra"),
                        ("terraform_state", "terraform_state"),
                        ("terraform_plan", "terraform_plan"),
                        ("terraform_dir", "terraform_dir")):
        value = getattr(args, flag, None)
        if value:
            layer[field] = tuple(value)
    targets: dict[str, TargetRef] = {}
    for raw in getattr(args, "target", None) or ():
        ref, problem = _parse_target(raw)
        if ref is not None:
            # Keyed by the document this invocation grounds — the same key shape
            # the config file's ``targets`` map uses, so one lookup serves both.
            targets[os.path.abspath(start)] = ref
        else:
            logger.debug("ignoring unusable --target %r: %s", raw, problem)
    if targets:
        layer["targets"] = targets
    # ``requirements`` has no slot in discovery's env layer — ``from_env``
    # resolves SourceOptions fields alone — so the CLI's own flag-then-
    # $GCP_GROUNDING_REQUIREMENTS resolution IS this layer's contribution, and
    # both therefore report the ``cli`` origin.
    requirements = _requirements_flag_or_env(args)
    if requirements:
        layer["requirements"] = requirements
    return layer


def _resolve_settings(args: argparse.Namespace, *, start: str
                      ) -> tuple[discovery.Settings, tuple[Verdict, ...]]:
    """The four layers — flags, environment, config file, auto-detection — as
    ONE :class:`~gcp_grounding.discovery.Settings`, plus every problem found
    along the way as a note.

    Discovery is rooted at *start* and walks UP from it, which is what gives a
    hook per-edited-file settings from one fixed command line. ``--no-config``
    suppresses both the config file and auto-detection: with it, the flags and
    the environment are the whole configuration.
    """
    env = os.environ
    config: discovery.Config | None = None
    auto: discovery.Auto | None = None
    problems: tuple[str, ...] = ()
    if not getattr(args, "no_config", False):
        named = getattr(args, "config", None)
        if named:
            # A NAMED config never falls through to auto-detection, even when it
            # fails to parse: the operator has said which file describes their
            # sources, and guessing one after theirs was refused would ground
            # against a source they never named.
            config, problems = discovery.load_config(named)
        else:
            config, problems = discovery.discover(start, env=env)
            if config is None:
                # Same rule one layer down: an operator who wrote a config has
                # already said what the sources are.
                auto, detected = discovery.auto_detect(start)
                problems += detected
    settings = discovery.resolve_settings(cli=_cli_layer(args, start), env=env,
                                          config=config, auto=auto)
    notes = tuple(Verdict("unverified", "provenance", start or "<settings>", 0,
                          problem) for problem in problems)
    return settings, notes


def _eval_options(args: argparse.Namespace, settings: discovery.Settings,
                  path: str) -> engine.EvalOptions:
    """Everything :func:`gcp_grounding.engine.evaluate` decides with.

    ``drift`` crosses one vocabulary boundary here and nowhere else: the loading
    side speaks :data:`gcp_grounding.drift.DRIFT_POLICIES` (annotate / block /
    abstain) and the engine speaks :data:`gcp_grounding.engine.DRIFT_MODES`
    (report / block). Only ``block`` means the same thing in both.
    """
    options = settings.options
    max_age = freshness.parse_duration(options.max_age) \
        if options.max_age is not None else freshness.MAX_AGE_DEFAULT
    policy = options.drift_policy or drift.DEFAULT_DRIFT_POLICY
    return engine.EvalOptions(
        as_of=options.now,
        max_age_seconds=None if max_age is None else int(max_age.total_seconds()),
        drift="block" if policy == "block" else engine.DEFAULT_DRIFT_MODE,
        auto_baseline=not getattr(args, "no_auto_baseline", False),
        hints=_hints(settings, path))


def _hints(settings: discovery.Settings, path: str) -> Hints:
    """The baseline hints for *path*: which estate row this document changes.

    An explicit ``--target`` is an ``explicit-flag`` identification and a config
    entry is a ``config-map`` one, so only a CLI target is put in ``target`` —
    the explain surface must be able to say WHICH of the two identified a
    counterpart, and collapsing them would make a config entry read as
    something a human typed on this command line.
    """
    refs = settings.targets
    absolute = os.path.abspath(path)
    ref = refs.get(absolute) or refs.get(path)
    from_flag = settings.origin_of("targets") == "cli"
    return Hints(
        target=(ref.key if ref is not None and from_flag else ""),
        category=(ref.category if ref is not None else ""),
        targets={key: value.key for key, value in refs.items()},
        source=absolute)


def _ground(args: argparse.Namespace, settings: discovery.Settings,
            snapshot: GcpSnapshot, notes: tuple[Verdict, ...], *, path: str,
            rules: Any, carried: Any) -> _Ground:
    """Ground *path* on whichever route this run's configuration chose.

    NO STATE CONFIGURED is the pre-existing path, unchanged, so a run that names
    only a snapshot is byte-identical to what it has always been. With a state
    source configured the three inputs meet in ``engine.evaluate``: the current
    state is assembled ONCE by ``sources.load_current``, every state-source
    verdict is added to the report, and the rule set carries the compiled
    requirements the engine will not load for itself.
    """
    if not _state_configured(settings):
        report = ground_policy(path, snapshot, baseline=args.baseline, rules=rules)
        # The carry verdicts are what keeps a rejected or unverified promise
        # visible: without them a requirement that did not run is
        # indistinguishable from one that passed.
        for verdict in carried:
            report.add(verdict)
        return _Ground(report=_finish_report(report, snapshot, notes))

    # THE CLOCK IS RESOLVED ONCE, HERE, and injected downward; nothing below
    # this boundary reads the wall clock.
    try:
        now = freshness.resolve_now(settings.options.now)
    except ValueError as exc:
        return _Ground(report=GroundingReport(), problem=str(exc))
    options = discovery.to_source_options(settings, as_of=now)
    settings = dataclasses.replace(settings, options=options)
    current = sources.load_current(options)
    if current.problem:
        return _Ground(report=GroundingReport(), current=current,
                       problem=current.problem)
    notes = notes + tuple(current.notes)

    document, error = _read_json(path)
    if error is not None:
        # There is no proposal to prepare. The one loader's fail-open shape is
        # still the honest answer, and it already says what could not be read.
        report = ground_policy(path, snapshot, baseline=args.baseline, rules=rules)
        for verdict in carried:
            report.add(verdict)
        return _Ground(report=_finish_report(report, current.snapshot or snapshot,
                                             notes),
                       current=current)

    proposal = engine.prepare_proposal(document, detect_kind(document), source=path)
    result = engine.evaluate(
        proposal, current, engine.RuleSet(compiled=tuple(rules),
                                          carry_verdicts=tuple(carried)),
        options=_eval_options(args, settings, path))
    report = result.report
    if args.baseline is not None:
        report.add(_explicit_baseline_verdict(document, args.baseline))
    return _Ground(report=_finish_report(report, current.snapshot or snapshot, notes),
                   current=current, result=result)


def _explicit_baseline_verdict(document: Any, path: str) -> Verdict:
    """``--baseline`` on the state route: the SAME new⊆old comparison the pair
    tier runs, against the document a human named.

    The flag keeps working here rather than being silently superseded by the
    derived baseline — an explicit path is the highest-fidelity statement about
    what the current policy is, so its answer is reported alongside the derived
    one and attributed to the file it came from.
    """
    old, error = _read_json(path)
    if error is not None:
        return Verdict("unverified", "subset", "iam-policy", 0,
                       f"the explicit baseline {path}: {error} — new⊆old was not "
                       f"decided")
    if not isinstance(old, Mapping) or not isinstance(document, Mapping):
        return Verdict("unverified", "subset", "iam-policy", 0,
                       f"new⊆old was not decided against the explicit baseline "
                       f"{path}: an IAM policy comparison needs two policy "
                       f"objects")
    try:
        verdict = check_policy_subset(document, old, get_solver())
    except ValueError as exc:
        return Verdict("unverified", "subset", "iam-policy", 0,
                       f"new⊆old was not decided against the explicit baseline "
                       f"{path}: {exc}")
    return Verdict(verdict.status, verdict.kind, verdict.target, verdict.lineno,
                   f"{verdict.message} [explicit baseline {path}]",
                   suggestions=verdict.suggestions)


def _finish_report(report: GroundingReport, snapshot: Any,
                   notes: tuple[Verdict, ...],
                   policy: str = drift.DEFAULT_DRIFT_POLICY) -> GroundingReport:
    """THE ONE finishing pass, so the normal and hook paths cannot drift apart.

    Adds the state notes, re-grades the existence verdicts the reasoner minted
    outside any check (:func:`gcp_grounding.drift.postpass` — an ``ungrounded``
    on a category no source enumerated completely is not a hallucination
    finding), re-attaches the secret filter to the live handler set and scrubs
    the report.

    Every step is a NO-OP on the no-state path — ``postpass`` returns unless
    *snapshot* is a reconciled one, and a vault that collected nothing scrubs
    nothing — which is what lets one helper serve both routes without the
    no-flag output moving by a byte.
    """
    for verdict in notes:
        report.add(verdict)
    drift.postpass(report, snapshot, policy)
    vault = sources.vault()
    redact.ensure_log_filter(vault)
    redact.scrub_report(vault, report)
    return report


def _state_document(ground: _Ground, settings: discovery.Settings) -> Any:
    """The ``state`` key's document, or ``None`` when state is off.

    Keyed on CONFIGURATION and not on load outcome, exactly as the ``sec`` key
    is: a consumer must be able to tell "every configured source failed"
    (``state.sources == []``) from "no state source is configured" (no ``state``
    key at all), which it cannot do if a failed load silently changes the shape.
    """
    if not _state_configured(settings):
        return None
    ledger = getattr(ground.current, "ledger", None)
    return explain_state.state_document(ground.result, ledger, settings)


def _state_explain_lines(ground: _Ground, settings: discovery.Settings,
                         argument: str) -> list[str]:
    """``--state-explain``'s stderr block: the four provenance blocks, or one
    target's drill-down when the flag carried a ``DOMAIN:KEY``."""
    ledger = getattr(ground.current, "ledger", None)
    if argument:
        domain, _, key = argument.partition(":")
        return explain_state.fact_lines(ground.result, ledger, domain.strip(),
                                        key.strip())
    return explain_state.state_lines(ground.result, ledger, settings)


def _incomplete_notice(ground: _Ground, settings: discovery.Settings, *,
                       hook: bool) -> None:
    """THE ONE LINE saying the current-state comparison was incomplete.

    A configured source that contributed nothing leaves the run comparing
    against less than it was told to, and every verdict that would have read the
    missing category answers from less evidence. That is invisible otherwise:
    every state verdict is ``unverified``, so the exit code is unchanged and the
    abstain channel defaults off — a silently inert baseline looks exactly like
    a passing one.

    NOT gated on ``--abstain-notes``, and it NEVER changes an exit code. Silent
    when every configured source loaded: a channel that fires on a healthy setup
    is noise, and noise is what gets a guardrail switched off — which is why the
    test is the FAILED sources and not the wider "any unqueried counterpart".
    A failed source is itself one of the incomplete-coverage kinds, so this is
    the stronger half of that condition and implies it; the weaker half alone
    fires on a perfectly healthy multi-source run, where a merged view withholds
    the existence licence and every counterpart is honestly unqueried.
    """
    if ground.current is None or not _state_configured(settings):
        return
    failed = [v for v in ground.report.verdicts if v.kind in _SOURCE_FAILED_KINDS]
    if not failed:
        return
    configured = settings.options.configured()
    print(f"{_prefix(hook)}: {len(failed)} of {len(configured)} configured state "
          f"source(s) contributed nothing, so the current-state comparison was "
          f"INCOMPLETE — every check reading a category they would have supplied "
          f"answered from less evidence (the exit code is unchanged)",
          file=sys.stderr)


def _not_a_proposal(path: str) -> Verdict | None:
    """One verdict when *path* is terraform STATE, or ``None`` to ground it.

    Runs BEFORE ``preflight.detect_kind``, which classifies a v4 state file as a
    plan — its key set carries ``terraform_version`` — extracts zero claims and
    prints a clean-looking pass over a file describing the whole estate.

    The sniff and the message are BOTH the shared ones
    (:func:`gcp_grounding.tfsource.discover.is_v4_state`,
    :data:`~gcp_grounding.tfsource.discover.STATE_NOT_A_PROPOSAL`), resolved
    lazily behind the established ImportError fail-open idiom: two hand-written
    sniffs and two message templates in two files with no shared owner will
    drift, and a drifted sniff is exactly the zero-claim clean pass this arm and
    the capture gate both exist to close.
    """
    document, error = _read_json(path)
    if error is not None:
        return None
    try:
        from .tfsource import discover
    except ImportError:
        # A DUPLICATE OF LAST RESORT, for the import-unavailable path ONLY: the
        # shared predicate and the shared message are both out of reach here, so
        # the alternative is grounding a state file as a plan.
        if not (isinstance(document, Mapping) and document.get("version") == 4
                and isinstance(document.get("resources"), list)
                and document.get("lineage")):
            return None
        logger.debug("gcp_grounding.tfsource.discover is not part of this "
                     "checkout — falling back to the inline state sniff")
        return Verdict("ungrounded", _STATE_DOCUMENT_KIND, path, 0,
                       f"{path}: this is Terraform state, not a proposed change "
                       f"— it was NOT graded as a proposal. Pass it with the "
                       f"terraform-state flag to use it as a baseline.")
    if not discover.is_v4_state(document):
        return None
    return Verdict("ungrounded", _STATE_DOCUMENT_KIND, path, 0,
                   discover.STATE_NOT_A_PROPOSAL.format(path=path))


# -- compiled requirements: pickup, notice, render -----------------------------


def _prefix(hook: bool) -> str:
    """The stderr line prefix for the mode we are in — the hook's stderr is
    agent-visible and its notes are already prefixed this way."""
    return "gcp-ground --hook" if hook else "gcp-ground verify-policy"


def _requirements_flag_or_env(args: argparse.Namespace) -> str | None:
    """``--requirements``, then :data:`REQUIREMENTS_ENV` — the CLI's own two
    layers, which is what :func:`_cli_layer` contributes to the settings.

    They are resolved together because ``discovery``'s environment layer is
    ``sources.from_env``, which knows the ``SourceOptions`` fields alone and has
    no slot for a settings-only field like ``requirements``.
    """
    flag = getattr(args, "requirements", None)
    if flag:
        return flag
    raw = os.environ.get(REQUIREMENTS_ENV)
    return raw.strip() if raw and raw.strip() else None


def _requirements_source(args: argparse.Namespace,
                         settings: discovery.Settings | None = None) -> str | None:
    """The CONFIGURED requirements location, or ``None`` when requirements are
    off: the flag, then :data:`REQUIREMENTS_ENV`, then a config file's
    ``requirements`` — the same precedence every other setting follows, read off
    the resolved settings rather than re-layered here.

    This answers "did the operator turn requirements on?", NOT "did any rule
    load" — the distinction is what keeps the ``--format json`` shape stable
    across a failed compile (see :func:`_render_policy`).
    """
    if settings is not None and settings.requirements:
        return settings.requirements
    return _requirements_flag_or_env(args)


def _load_requirements(source: str | None, *, hook: bool) -> tuple[tuple, tuple]:
    """→ ``(rules, carry_verdicts)`` for the configured *source*.

    Never raises and never blocks. :mod:`~gcp_grounding.sec_rules` is resolved
    with importlib — mirroring preflight's dynamic ``tf_claims`` resolution — so
    a checkout without the sec modules, or an unreadable artifact directory,
    prints one stderr note and proceeds with no rules. A broken requirements
    setup must never block an edit; that is the module docstring's promise, and
    it outranks running any particular rule.
    """
    if source is None:
        return (), ()
    prefix = _prefix(hook)
    try:
        sec_rules = importlib.import_module("gcp_grounding.sec_rules")
    except ImportError as exc:
        print(f"{prefix}: compiled requirements are not available in this "
              f"checkout ({exc}) — none were loaded", file=sys.stderr)
        return (), ()
    if not os.path.exists(source) or not os.access(source, os.R_OK):
        print(f"{prefix}: the requirements at {source} could not be read — "
              f"none were loaded", file=sys.stderr)
        return (), ()
    try:
        if os.path.isdir(source):
            rules, verdicts = sec_rules.load_directory(source)
        else:
            rules, verdicts = sec_rules.load_rules([source])
    except (OSError, ValueError) as exc:
        print(f"{prefix}: the requirements at {source} could not be loaded "
              f"({exc}) — none were loaded", file=sys.stderr)
        return (), ()
    _requirements_notice(rules, verdicts, source=source, hook=hook)
    return tuple(rules), tuple(verdicts)


def _requirements_notice(rules, verdicts, *, source: str, hook: bool) -> None:
    """Print the ONE operator line when a loaded promise is not enforcing.

    Without this line a broken requirement is INVISIBLE in the mode operators
    actually run. ``sec_rules`` maps a ``rejected`` promise to an ``unverified``
    carry verdict — whose rationale is sound, since one bad requirement file
    must not fail every unrelated policy run — so ``report.ok`` stays True, and
    ``--abstain-notes`` defaults off. Dropping a typo'd requirement into
    ``sec_requirements/`` and running the hook would then yield exit 0 with
    byte-empty stderr and zero enforcement: byte-identical to the rule working.

    So this channel is deliberately NOT gated on ``--abstain-notes``. The whole
    point is that the operator has not opted into anything and still needs to
    know their guardrail is inert. It NEVER changes an exit code — a notice that
    could block would resurrect the fail-closed hole the hook's fail-open
    contract closed.

    Silence when every loaded promise enforces: a channel that fires on a
    healthy configuration is noise, and noise is what gets a guardrail switched
    off.
    """
    enforcing = {rule.promise.id for rule in rules}
    # A non-compiled promise exists ONLY as a carry verdict — there is no
    # whole-artifact status accessor — so the stalled set is read off the
    # verdicts that do not belong to a registered rule.
    stalled = {verdict.target for verdict in verdicts
               if verdict.target not in enforcing}
    if not stalled:
        return
    print(f"{_prefix(hook)}: {len(stalled)} of {len(enforcing) + len(stalled)} "
          f"compiled requirement(s) are not enforcing (see "
          f"compile-requirements) — {source}", file=sys.stderr)


def _witness_table(sec_evidence: Any, sec_rules: Any, rules) -> Any:
    """The evidence side-table for the ``sec`` document: each rule's two pinned
    witnesses, plus the record that refuted it this run, if any.

    Record fields may be bools or ints, and
    :class:`~gcp_grounding.sec_evidence.WitnessRow` refuses a non-string
    assignment rather than guessing a rendering — so they are stringified here,
    at the boundary.
    """
    table = sec_evidence.WitnessTable()
    for rule in rules:
        promise = rule.promise
        for role, witness in (("pinned-positive", promise.positive),
                              ("pinned-negative", promise.negative)):
            if witness is None:
                continue
            table.add(sec_evidence.WitnessRow(
                promise_id=promise.id, role=role,
                assignment=dict(witness.assignment)))
        found = sec_rules.last_witness(promise.id)
        if found:
            table.add(sec_evidence.WitnessRow(
                promise_id=promise.id, role="violating-record",
                collection=found["collection"], index=found["index"],
                assignment={k: str(v) for k, v in found["record"].items()}))
    return table


def _render_policy(policy_report: PolicyReport, format: str,
                   source: str | None, rules, state: Any = None) -> str:
    """The stdout render, one document.

    ``--format json`` becomes :func:`sec_evidence.sec_document` whenever a
    requirements source was CONFIGURED — even when it resolved to zero rules —
    so a consumer that turned requirements on always sees the same shape and can
    tell "no rules loaded" (``sec.requirements == []``) from "requirements are
    off" (no ``sec`` key at all). Keying that on the LOAD OUTCOME instead would
    make the document shape depend on whether a compile succeeded, which is
    exactly the ambiguity the always-present nested key removes.

    ``state`` is added under the SAME discipline: present whenever a state
    source was configured, even when every one of them failed to load. With
    neither configured this is byte-identical to what it has always been.
    """
    if format != "json" or (source is None and state is None):
        return policy_report.render(_FORMATS[format])
    document: Any = policy_report.to_dict()
    if source is not None:
        document = _sec_document(policy_report, rules, document)
    if state is not None:
        document["state"] = state
    # Rendered exactly as report.py renders its own JSON, so the two documents
    # differ only by the added key(s).
    return json.dumps(document, indent=2, ensure_ascii=False)


def _sec_document(policy_report: PolicyReport, rules, fallback: Any) -> Any:
    """The ``sec``-bearing document, or *fallback* where the evidence channel is
    not part of this checkout — the same fail-open as the pickup: the base
    document is still true, it just carries no evidence table."""
    try:
        sec_evidence = importlib.import_module("gcp_grounding.sec_evidence")
        sec_rules = importlib.import_module("gcp_grounding.sec_rules")
    except ImportError:
        logger.debug("the sec evidence channel is unavailable", exc_info=True)
        return fallback
    return sec_evidence.sec_document(
        policy_report, _witness_table(sec_evidence, sec_rules, rules), rules)


def _sec_explain_lines(source: str | None, rules) -> list[str]:
    """The ``--explain`` stanzas for the compiled requirements, or ``[]``.

    Each loaded promise's s-expression and pinned witnesses print next to the
    CEL and subset formulas: the reviewer's cross-check that what shipped in the
    artifact is what actually ran.
    """
    if source is None:
        return []
    try:
        sec_evidence = importlib.import_module("gcp_grounding.sec_evidence")
    except ImportError:
        logger.debug("the sec evidence channel is unavailable", exc_info=True)
        return []
    return ["compiled requirements loaded this run:",
            *sec_evidence.explain_lines(rules)]


# -- --hook: Claude-Code PostToolUse ------------------------------------------


def _run_hook(args: argparse.Namespace) -> int:
    """Ground the file a PostToolUse event says was edited. Fail-open: only
    a real ungrounded/contradicted finding — or a mutating shell command under
    the default ``block`` policy — exits nonzero.

    :func:`_hook_bash` runs FIRST, before the scope skip, before the path and
    suffix filter, and before the snapshot is resolved: a shell scan needs no
    snapshot, so it must keep working when the snapshot is missing or broken —
    otherwise the cheapest bypass (run ``gcloud``, write no file) would also be
    the one an unconfigured hook waves through.

    :func:`_hook_scope_skip` runs next and decides whether a file event is in
    scope at all — a read-only tool, or a ``PreToolUse`` file edit, never
    reaches the grounding pass.

    When the gate passes and :func:`_abstain_notes` is enabled, the verdicts it
    could not judge go to stderr before the exit-0 return. That channel is
    reporting only: it NEVER changes an exit code, in any case, and it lives
    inside the ``report.ok`` arm, so a blocking run renders its report exactly
    as before.
    """
    event = _read_hook_event(sys.stdin)
    if event is None:
        return EXIT_OK
    bash = _hook_bash(event, args)
    if bash is not None:
        return bash
    skip = _hook_scope_skip(event)
    if skip is not None:
        if skip:
            print(f"gcp-ground --hook: {skip}", file=sys.stderr)
        else:
            logger.debug("--hook: out of scope (tool_name=%r)",
                         event.get("tool_name"))
        return EXIT_OK
    path = _hook_file_path(event)
    # casefold() mirrors the gate's case-insensitive suffix match: an edited
    # 'IAM.POLICY.JSON' is a policy document too.
    if path is None or not path.casefold().endswith(_HOOK_SUFFIXES):
        logger.debug("--hook: nothing to ground (path=%r)", path)
        return EXIT_OK
    # EVERY STATE PROBLEM IN HOOK MODE IS FAIL-OPEN: one prefixed note and exit
    # 0, never a usage error. A misconfigured hook must degrade to checking
    # nothing, never to blocking every edit.
    problem = _state_flag_problem(args)
    if problem is not None:
        return _usage(problem, hook=True)
    # ROOTED AT THE EDITED FILE, so discovery walks up from it: one hook command
    # line, per-file state. That is what makes auto-baseline work for an agent
    # moving between terraform roots in one repo.
    settings, notes = _resolve_settings(args, start=path)
    snapshot, more, problem = _load_snapshot(args, settings=settings)
    if snapshot is None:
        print(f"gcp-ground --hook: {problem} — nothing was checked (fail-open)",
              file=sys.stderr)
        return EXIT_OK
    notes += more
    refusal = _not_a_proposal(path)
    if refusal is not None:
        return _usage(refusal.message, hook=True)
    # Requirements are resolved only once this event is genuinely being
    # grounded: an out-of-scope or non-policy event must stay byte-silent, so
    # the not-enforcing notice rides along with a real run, never with a skip.
    source = _requirements_source(args, settings)
    rules, carried = _load_requirements(source, hook=True)
    ground = _ground(args, settings, snapshot, notes, path=path, rules=rules,
                     carried=carried)
    if ground.problem is not None:
        return _usage(ground.problem, hook=True)
    report = ground.report
    if args.explain:
        lines = _explain_lines(path, args.baseline)
        lines.extend(_sec_explain_lines(source, rules))
        lines.extend(_state_explain_lines(ground, settings, ""))
        print("\n".join(lines), file=sys.stderr)
    if args.state_explain is not None:
        print("\n".join(_state_explain_lines(ground, settings, args.state_explain)),
              file=sys.stderr)
    _incomplete_notice(ground, settings, hook=True)
    if report.ok:
        if _abstain_notes(args):
            notes = _abstain_note_lines(report, snapshot.captured_at)
            if notes:
                print("\n".join(notes), file=sys.stderr)
        return EXIT_OK
    rendered = PolicyReport(report, captured_at=snapshot.captured_at,
                            source=path).render("human")
    print(rendered, file=sys.stderr)
    return EXIT_BLOCK


def _read_hook_event(stream: Any) -> Mapping[str, Any] | None:
    try:
        event = json.load(stream)
    except (ValueError, UnicodeDecodeError, OSError) as exc:
        print(f"gcp-ground --hook: stdin is not a JSON event ({exc}) — "
              f"nothing was checked (fail-open)", file=sys.stderr)
        return None
    if not isinstance(event, Mapping):
        print(f"gcp-ground --hook: event is {type(event).__name__}, not an "
              f"object — nothing was checked (fail-open)", file=sys.stderr)
        return None
    return event


def _hook_scope_skip(event: Mapping[str, Any]) -> str | None:
    """Why this event must not be grounded, or ``None`` to proceed.

    The empty string means "skip silently" (nothing happened that a guardrail
    should have an opinion about); a non-empty string is the explanation to
    print on stderr before skipping. See the module docstring for why the
    scope is a deny-list and why ``PreToolUse`` file events are declined
    rather than judged.
    """
    tool_name = event.get("tool_name")
    if isinstance(tool_name, str) and tool_name in _READ_ONLY_TOOLS:
        return ""  # a read is not a change — there is nothing to judge
    if event.get("hook_event_name") == "PreToolUse":
        path = _hook_file_path(event)
        if path:
            # The edit has not landed, so grounding the disk content would
            # judge the wrong document. Abstain out loud, and say how to fix
            # the registration.
            return (f"PreToolUse for {path}: the edit has not landed yet, so "
                    f"the file on disk is still the pre-edit content — "
                    f"grounding it would judge the wrong document. Nothing "
                    f"was checked; register this hook on PostToolUse to "
                    f"ground the file the agent actually wrote.")
    return None


def _hook_file_path(event: Mapping[str, Any] | None) -> str | None:
    if event is None:
        return None
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, Mapping):
        return None
    path = tool_input.get("file_path")
    return path if isinstance(path, str) and path else None


# -- --hook: the abstain channel ----------------------------------------------


def _abstain_notes(args: argparse.Namespace) -> bool:
    """Whether ``--hook`` should print what it could not judge.

    The flag wins; otherwise :data:`ABSTAIN_NOTES_ENV` enables the channel when
    it is one of :data:`_TRUTHY_ENV`, case-insensitively. Anything else —
    ``"off"``, ``"0"``, the empty string, a typo — is False: an opt-in channel
    that guessed would be an opt-out one.
    """
    if getattr(args, "abstain_notes", False):
        return True
    raw = os.environ.get(ABSTAIN_NOTES_ENV)
    return raw is not None and raw.strip().casefold() in _TRUTHY_ENV


def _abstain_note_lines(report: GroundingReport, captured_at: str) -> list[str]:
    """The stderr block naming every claim the gate could not judge, or ``[]``.

    Empty when nothing is ``unverified``: no notes means no header, because a
    channel that fires on a clean pass is noise, and noise is what gets a
    guardrail switched off.

    Deliberately NOT :meth:`PolicyReport.render` — that prints the PASSED
    header and every grounded line too, and this channel is for the ignorance
    alone. The per-line shape is still the render's (:data:`_ABSTAIN_MARK`,
    :data:`_ABSTAIN_STAMPED`), so an operator reading hook stderr sees the same
    lines here and in a blocking report.
    """
    unverified = report.by_status("unverified")
    if not unverified:
        return []
    stamp = f" [snapshot {captured_at}]" if _ABSTAIN_STAMPED else ""
    lines = [f"gcp-ground --hook: NOT DECIDED — {len(unverified)} claim(s) "
             f"could not be judged (exit 0, nothing blocked)"]
    lines.extend(f"  {_ABSTAIN_MARK} [{v.kind}] {v.message}{stamp}"
                 for v in unverified)
    return lines


# -- --hook: the bash arm ------------------------------------------------------


def _hook_bash(event: Mapping[str, Any],
               args: argparse.Namespace) -> int | None:
    """The exit code for a command-bearing event, or ``None`` when this event
    carries no command and the file arm should handle it.

    ENGAGEMENT RULE: engage whenever ``tool_input.command`` is a non-empty
    string, whatever the ``tool_name`` says. That deliberately covers ``Bash``
    and any mcp or shell-ish tool that carries a command, and it is safe
    because a finding only ever arises for a recognized CLI basename at
    ``argv[0]`` — a non-shell field that happens to be called ``command`` will
    not have ``gcloud`` there.

    A command-bearing event belongs to this arm alone: Claude-Code events carry
    either a ``command`` or a ``file_path``, never both, so returning an exit
    code here takes nothing away from the file arm.
    """
    command = _hook_command(event)
    if command is None:
        return None
    policy = _bash_policy(args)
    if policy == "off":
        logger.debug("--hook: --bash-policy=off — the command was not scanned")
        return EXIT_OK
    source = str(event.get("tool_name") or "Bash")
    try:
        from .bash_mutation import bash_mutation_verdicts
    except ImportError:
        # Honest degradation, mirroring preflight's tf_claims arm: say that
        # nothing was checked rather than passing as though it had been.
        print("gcp-ground --hook: the bash-mutation classifier is not "
              "available — the command was not checked (fail-open)",
              file=sys.stderr)
        return EXIT_OK
    verdicts = bash_mutation_verdicts(command, source=source)
    if not verdicts:
        # Nothing in the command was recognized as GCP-mutating. Silence is the
        # contract here: the hook's stderr is agent-visible.
        logger.debug("--hook: no GCP mutation recognized in the command")
        return EXIT_OK
    mutating = [v for v in verdicts if v.kind == _BASH_MUTATION_KIND]
    blocking = policy == "block" and bool(mutating)
    print("\n".join(_bash_hook_lines(verdicts, event=event, policy=policy,
                                     blocking=blocking, source=source)),
          file=sys.stderr)
    # Unrecognized-only findings NEVER block: that is the abstain-with-message
    # contract, and `warn` always exits 0 by definition.
    return EXIT_BLOCK if blocking else EXIT_OK


def _hook_command(event: Mapping[str, Any]) -> str | None:
    """The shell command this event carries, or ``None`` — see the engagement
    rule in :func:`_hook_bash`."""
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, Mapping):
        return None
    command = tool_input.get("command")
    return command if isinstance(command, str) and command else None


def _bash_policy(args: argparse.Namespace) -> str:
    """The effective ``--bash-policy``: the flag, then the environment, then
    :data:`_DEFAULT_BASH_POLICY`.

    An unrecognized environment value prints ONE note and falls back to the
    default. It is never a usage error: this whole arm exists because a
    fail-closed argv hole is how the bypass stayed open, and turning a stale
    exported variable into an exit-2 usage error would reopen it from the other
    side — every tool call in the session failing until someone unsets it.
    """
    flag = getattr(args, "bash_policy", None)
    if flag in _BASH_POLICIES:
        return flag
    raw = os.environ.get(BASH_POLICY_ENV)
    if raw is None or not raw.strip():
        return _DEFAULT_BASH_POLICY
    value = raw.strip()
    if value in _BASH_POLICIES:
        return value
    print(f"gcp-ground --hook: ${BASH_POLICY_ENV}={raw!r} is not one of "
          f"{', '.join(_BASH_POLICIES)} — using --bash-policy="
          f"{_DEFAULT_BASH_POLICY}", file=sys.stderr)
    return _DEFAULT_BASH_POLICY


def _bash_hook_lines(verdicts: list[Verdict], *, event: Mapping[str, Any],
                     policy: str, blocking: bool, source: str) -> list[str]:
    """The stderr block for a command-bearing event with findings."""
    if any(v.kind == _BASH_MUTATION_KIND for v in verdicts):
        decision = "BLOCKED" if policy == "block" else "WARNING"
        headline = f"{decision} — unchecked GCP mutation in a shell command"
    else:
        headline = "NOT DECIDED — a shell command could not be classified"
    lines = [f"gcp-ground --hook: {headline}"]
    rendered = _bash_report(verdicts, source=source).render("human")
    # The per-verdict lines come from the shared renderer so the hook and
    # `scan-command` cannot drift; its summary header is dropped because it
    # reads "PASSED … ungrounded=0 contradicted=0" — true of the *report*, and
    # actively misleading directly under a BLOCKED headline.
    lines.extend(rendered.splitlines()[1:])
    lines.append(_bash_timing_line(event, blocking))
    lines.append("  Express this change as a policy document or `terraform "
                 "show -json` plan output so the gate can check it — or pass "
                 "--bash-policy=warn if the command is intentional.")
    return lines


def _bash_timing_line(event: Mapping[str, Any], blocking: bool) -> str:
    """What the operator can still do about it, which depends entirely on
    whether the command has run yet.

    ``PreToolUse`` is the correct registration point for ``Bash``: it is the one
    place this hook can intervene *before* the estate changes, and unlike a file
    edit there is no stale-disk problem, because the command text is in the
    event itself.
    """
    if event.get("hook_event_name") == "PreToolUse":
        if blocking:
            return ("  The command was blocked before execution — the estate "
                    "has not changed.")
        return ("  The command has not run yet and was NOT blocked, so it is "
                "about to execute — verify the estate afterwards and revert "
                "the change if it was unintended.")
    return ("  The command has already executed — verify the estate and revert "
            "the change if it was unintended.")


def _bash_report(verdicts: list[Verdict], *, source: str) -> PolicyReport:
    """The bash findings as a :class:`~gcp_grounding.report.PolicyReport`.

    Every bash verdict is ``unverified``, so ``report.ok`` stays True and the
    document never claims the gate refuted anything — the block is a policy
    decision made by the caller, not a verdict.
    """
    report = GroundingReport(backend=_BASH_BACKEND)
    for verdict in verdicts:
        report.add(verdict)
    return PolicyReport(report, captured_at=_BASH_CAPTURED_AT, source=source)


# -- scan-command --------------------------------------------------------------


def _cmd_scan_command(args: argparse.Namespace) -> int:
    """Classify one command and print the report. Exit 0, always.

    THE AUDIT TRAIL. Without this surface a bypass attempt exists only as hook
    stderr: nothing lands in ``PolicyReport.to_dict()``, in ``--format json`` or
    in a CI artifact, so nobody can tell afterwards that anyone tried. The
    findings here are the same ones the hook renders, keyed on the
    ``bash-mutation`` kind and the message text, which is what lets a test (or a
    CI job) assert on structure instead of on stderr substrings.
    """
    command = sys.stdin.read() if args.command == "-" else args.command
    try:
        from .bash_mutation import bash_mutation_verdicts
    except ImportError:
        # No report at all rather than an empty one: a zero-verdict document
        # here would be indistinguishable from "this command is fine".
        print("gcp-ground scan-command: the bash-mutation classifier is not "
              "available — the command was not checked (fail-open)",
              file=sys.stderr)
        return EXIT_OK
    verdicts = bash_mutation_verdicts(command, source="scan-command")
    print(_bash_report(verdicts, source=command.strip()).render(
        _FORMATS[args.format]))
    return EXIT_OK


# -- compile-requirements ------------------------------------------------------


def _cmd_compile_requirements(args: argparse.Namespace) -> int:
    """Run stage 1 over a directory of markdown requirements.

    EXIT 0 means compiled or honestly unverified, 1 means a rejected promise or
    artifact drift, 2 means a usage or snapshot error — the gate's own contract,
    read over the compile instead of over a policy.

    The snapshot is REQUIRED, and its absence is a usage error rather than the
    fail-open the hook grants: compiling without a snapshot cannot ground a
    requirement's vocabulary, so a promise naming a hallucinated role would
    compile clean and ship as a rule that can never fire. Unlike hook mode there
    is no edit to unblock here, so there is nothing to trade the honesty for.
    """
    # Same four-layer resolution as ``verify-policy``, rooted at the requirement
    # directory: a checkout that names its snapshot in a config file must not
    # have to name it again here. The notes are discarded rather than added to a
    # report, because this command's report is about the COMPILE.
    snapshot, notes, problem = _load_snapshot(args, start=str(args.directory))
    if snapshot is None:
        return _usage(problem, prog="compile-requirements")
    for note in notes:
        logger.debug("compile-requirements: %s", note.message)
    try:
        sec_compile = importlib.import_module("gcp_grounding.sec_compile")
    except ImportError as exc:
        return _usage(f"the requirements compiler is not available in this "
                      f"checkout ({exc})", prog="compile-requirements")
    _llm_note(args.llm, sec_compile)
    out_dir = args.out or os.path.join(args.directory, "compiled")
    results = sec_compile.compile_directory(
        args.directory, snapshot, out_dir=out_dir, check_only=args.check,
        independence=not args.no_independence)
    # One report for the whole directory: a per-document render would make the
    # exit code and the printed evidence disagree about what "the compile" was.
    merged = GroundingReport(backend=get_solver().backend)
    for result in results:
        for verdict in result.report.verdicts:
            merged.add(verdict)
    print(PolicyReport(merged, captured_at=snapshot.captured_at,
                       source=str(args.directory)).render(_FORMATS[args.format]))
    # ``_emit`` already records drift as a contradicted sec:artifact verdict, so
    # merged.ok covers it; the explicit check keeps the contract readable and
    # holds even if a future drift becomes verdict-free.
    drifted = any(result.drifted for result in results)
    return EXIT_OK if merged.ok and not drifted else EXIT_FAILED


def _llm_note(enabled: bool, sec_compile: Any) -> None:
    """``--llm`` is optional in the strongest sense: it never hard-fails.

    The LLM-assisted stage lives in :mod:`gcp_grounding.sec_llm`, which is not
    part of every checkout, and stage 1 is deterministic and complete without
    it. So a missing module — or a compiler in this build that exposes no seam
    to hand it to — is one stderr note and a deterministic compile, never an
    error: refusing to compile because an OPTIONAL accelerator is absent would
    make the honest path the harder one.
    """
    if not enabled:
        return
    note = "gcp-ground compile-requirements: --llm"
    try:
        found = importlib.util.find_spec("gcp_grounding.sec_llm") is not None
    except (ImportError, ValueError):
        found = False
    if not found:
        print(f"{note}: gcp_grounding.sec_llm is not available in this checkout "
              f"— compiling deterministically", file=sys.stderr)
        return
    if "llm" not in inspect.signature(sec_compile.compile_directory).parameters:
        print(f"{note}: this build's compiler exposes no LLM-assisted stage — "
              f"compiling deterministically", file=sys.stderr)


# -- --explain: the z3 constraints generated this run --------------------------


def _explain_lines(file: str, baseline: str | None) -> list[str]:
    """Re-derive the z3 formulas the constraint layer built for *file* (and
    *baseline*, if the subset comparison ran) and render their s-expressions."""
    solver = get_solver()
    z3 = _z3_module(solver)
    lines = [f"z3 constraints generated this run [{solver.backend}]:"]
    if z3 is None:
        lines.append("  (z3 is not available — no constraints were generated; "
                     "cel and subset checks degraded to 'unverified')")
        return lines
    doc, error = _read_json(file)
    if error is not None:
        lines.append(f"  ({error} — no constraints were generated)")
        return lines
    kind = detect_kind(doc)
    for claim in _claims_for_explain(doc, kind):
        if claim.kind != "cel":
            continue
        try:
            formula = _CelToZ3(z3, claim.value).translate()
        except UnsupportedCel as exc:
            lines.append(f"  [cel] {claim.location}: no constraint — CEL outside "
                         f"the supported subset ({exc})")
        else:
            lines.append(f"  [cel] {claim.location}: {formula.sexpr()}")
    if baseline is not None and kind == "iam_policy":
        lines.append(_explain_subset(z3, doc, baseline))
    if len(lines) == 1:
        lines.append("  (no z3 constraints were generated this run)")
    return lines


def _explain_subset(z3: Any, doc: Mapping[str, Any], baseline: str) -> str:
    """The new⊈old satisfiability assertion, as check_policy_subset encodes
    it: sat ⇒ a witness grant breaks the subset claim."""
    old_doc, error = _read_json(baseline)
    if error is not None:
        return f"  [subset] no constraint — baseline {error}"
    if not isinstance(old_doc, Mapping):
        return (f"  [subset] no constraint — the baseline policy is "
                f"{type(old_doc).__name__}, not an object")
    try:
        new_grants = _grant_pairs(doc, "new")
        old_grants = _grant_pairs(old_doc, "old")
    except _Undecidable as exc:
        return f"  [subset] no constraint — {exc}"
    role = z3.String("role")
    member = z3.String("member")
    cond_cache: dict = {}

    def granted(grants):
        if not grants:
            return z3.BoolVal(False)
        return z3.Or([z3.And(role == z3.StringVal(r), member == z3.StringVal(m),
                             _condition_formula(z3, c, cond_cache))
                      for r, m, c in sorted(grants, key=lambda t: (t[0], t[1], t[2] or ""))])

    try:
        assertion = z3.And(granted(new_grants), z3.Not(granted(old_grants)))
    except (UnsupportedCel, RecursionError) as exc:
        return f"  [subset] no constraint — a condition is CEL outside the supported subset ({exc})"
    return f"  [subset] iam-policy: {assertion.sexpr()}"


def _claims_for_explain(doc: Any, kind: str | None) -> list[Any]:
    """The same claims preflight extracted, fail-open to none. The tf-plan
    extractor is resolved dynamically, exactly as preflight resolves it."""
    if kind == "iam_policy":
        extract = iam_policy_claims
    elif kind == "org_policy":
        extract = org_policy_claims
    elif kind == "tf_plan":
        try:
            module = importlib.import_module("gcp_grounding.tf_claims")
        except ImportError:
            return []
        extract = module.terraform_plan_claims
    else:
        return []
    try:
        return list(extract(doc))
    except Exception:  # fail-open, mirroring preflight's extraction contract
        logger.debug("--explain: claim extraction failed", exc_info=True)
        return []


def _read_json(path: str) -> tuple[Any, str | None]:
    """→ (document, error) — exactly one is meaningful; never raises."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), None
    except OSError as exc:
        return None, f"the document could not be read ({exc})"
    except json.JSONDecodeError as exc:
        return None, f"the document is not valid JSON ({exc})"
    except (ValueError, RecursionError) as exc:
        # Non-UTF-8 bytes (UnicodeDecodeError) and deeply nested JSON
        # (RecursionError) — same fail-open arm as preflight._load_document.
        return None, (f"the document could not be parsed "
                      f"({type(exc).__name__}: {exc})")
