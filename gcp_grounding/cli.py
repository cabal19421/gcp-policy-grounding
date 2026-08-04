"""Command-line interface: ``gcp-ground verify-policy`` / ``scan-command`` /
``compile-requirements``.

Three subcommands, exposed both as the ``gcp-ground`` console script and as
``python -m gcp_grounding``::

    gcp-ground verify-policy FILE [--snapshot PATH] [--baseline PATH]
                             [--format text|json] [--explain] [--hook]
                             [--bash-policy block|warn|off] [--abstain-notes]
                             [--requirements PATH]
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

``--hook`` reads a Claude-Code PostToolUse event (JSON on stdin), pulls the
edited file out of ``tool_input.file_path``, and grounds it when it looks
like a policy document (``.tf``/``.json``, case-insensitive, matching the
gate's suffix rules). Everything else — unparsable
events, missing paths, non-policy files, an unavailable snapshot — exits 0:
a broken hook setup must never block an edit. A raw ``.tf`` file is not
``terraform show -json`` output, so it lands in ``unverified`` via the
preflight fail-open contract and passes, honestly unjudged.

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
- ``1`` — a promise was ``rejected``, ``--check`` found artifact drift, NOTHING
  was compiled, or the output directory holds an artifact this compile did not
  produce (an orphan whose source document was deleted, which the pickup still
  loads and enforces);
- ``2`` — a usage error, including a missing or unreadable ``--snapshot``, a
  ``DIR`` that is not a directory, and an unwritable ``--out``.

COMPILING NOTHING IS NOT A PASS. An empty walk used to render a report over zero
verdicts, which is trivially ``ok``, so a renamed corpus directory exited 0 with
byte-empty stderr — including in ``--check``, the mode whose whole purpose is
keeping committed artifacts honest.

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
source resolves and any loaded promise is not enforcing — OR the source resolved
and no rules loaded AT ALL, which is what a clean checkout or a fresh CI
container reaches by simply not having run the compiler yet — ONE line goes to
stderr on every run, in both hook and normal mode, naming the artifact
directory. The exit code is unchanged in every case: this is a notice, never a
block, so it cannot resurrect the fail-closed hole ``--hook``'s fail-open
contract closed.
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

stdlib ``argparse`` only — no third-party CLI framework.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import inspect
import json
import os
import sys
from typing import Any, Mapping

from .claims import iam_policy_claims, org_policy_claims
# Explain reuses the constraint layer's own encoders (private to the package,
# not the world) — re-implementing the CEL translation here would let the
# dumped formulas drift from the ones actually decided.
from .constraints import (
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
    snapshot, problem = _load_snapshot(args.snapshot)
    if snapshot is None:
        return _usage(problem)
    source = _requirements_source(args)
    rules, carried = _load_requirements(source, hook=False)
    report = ground_policy(args.file, snapshot, baseline=args.baseline,
                           rules=rules)
    # The carry verdicts are what keeps a rejected or unverified promise
    # visible: without them a requirement that did not run is indistinguishable
    # from one that passed.
    for verdict in carried:
        report.add(verdict)
    policy_report = PolicyReport(report, captured_at=snapshot.captured_at,
                                 source=args.file)
    print(_render_policy(policy_report, args.format, source, rules))
    if args.explain:
        lines = _explain_lines(args.file, args.baseline)
        lines.extend(_sec_explain_lines(source, rules))
        print("\n".join(lines), file=sys.stderr)
    return EXIT_OK if report.ok else EXIT_FAILED


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


def _load_snapshot(flag: str | None) -> tuple[GcpSnapshot | None, str | None]:
    """→ (snapshot, problem) — exactly one is meaningful; never raises."""
    path = flag or os.environ.get(SNAPSHOT_ENV)
    if not path:
        return None, (f"an estate snapshot is required: pass --snapshot PATH "
                      f"or set ${SNAPSHOT_ENV}")
    try:
        return GcpSnapshot.load(path), None
    except OSError as exc:
        return None, f"snapshot {path}: could not be read ({exc})"
    except ValueError as exc:
        return None, str(exc)  # GcpSnapshot.load already names the path


# -- compiled requirements: pickup, notice, render -----------------------------


def _prefix(hook: bool) -> str:
    """The stderr line prefix for the mode we are in — the hook's stderr is
    agent-visible and its notes are already prefixed this way."""
    return "gcp-ground --hook" if hook else "gcp-ground verify-policy"


def _requirements_source(args: argparse.Namespace) -> str | None:
    """The CONFIGURED requirements location, or ``None`` when requirements are
    off. The flag wins, then :data:`REQUIREMENTS_ENV`.

    This answers "did the operator turn requirements on?", NOT "did any rule
    load" — the distinction is what keeps the ``--format json`` shape stable
    across a failed compile (see :func:`_render_policy`).
    """
    flag = getattr(args, "requirements", None)
    if flag:
        return flag
    raw = os.environ.get(REQUIREMENTS_ENV)
    return raw.strip() if raw and raw.strip() else None


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

    ZERO RULES FIRES REGARDLESS OF THE VERDICTS. The stalled set is derived from
    the carry verdicts, so a source that RESOLVED and produced no artifact at all
    produced no verdicts either, an empty stalled set, and — before this branch —
    no notice: byte-identical to the rule working, which is the one state this
    channel exists to make impossible. It is also the likeliest one in the field,
    because compiled artifacts are GENERATED: a clean checkout or a fresh CI
    container leaves the directory present and empty while the environment
    variable stays exported. The exit code is untouched here as everywhere else.
    """
    enforcing = {rule.promise.id for rule in rules}
    # A non-compiled promise exists ONLY as a carry verdict — there is no
    # whole-artifact status accessor — so the stalled set is read off the
    # verdicts that do not belong to a registered rule.
    stalled = {verdict.target for verdict in verdicts
               if verdict.target not in enforcing}
    if not enforcing:
        print(f"{_prefix(hook)}: 0 compiled requirement(s) loaded from {source} "
              f"— nothing is being enforced (see compile-requirements)",
              file=sys.stderr)
        return
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
                   source: str | None, rules) -> str:
    """The stdout render, one document.

    ``--format json`` becomes :func:`sec_evidence.sec_document` whenever a
    requirements source was CONFIGURED — even when it resolved to zero rules —
    so a consumer that turned requirements on always sees the same shape and can
    tell "no rules loaded" (``sec.requirements == []``) from "requirements are
    off" (no ``sec`` key at all). Keying that on the LOAD OUTCOME instead would
    make the document shape depend on whether a compile succeeded, which is
    exactly the ambiguity the always-present nested key removes.

    With no source configured this is byte-identical to what it has always been.
    """
    if source is None or format != "json":
        return policy_report.render(_FORMATS[format])
    try:
        sec_evidence = importlib.import_module("gcp_grounding.sec_evidence")
        sec_rules = importlib.import_module("gcp_grounding.sec_rules")
    except ImportError:
        # Same fail-open as the pickup: the base document is still true, it just
        # carries no evidence table.
        logger.debug("the sec evidence channel is unavailable", exc_info=True)
        return policy_report.render(_FORMATS[format])
    document = sec_evidence.sec_document(
        policy_report, _witness_table(sec_evidence, sec_rules, rules), rules)
    # Rendered exactly as report.py renders its own JSON, so the two documents
    # differ only by the added key.
    return json.dumps(document, indent=2, ensure_ascii=False)


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
    snapshot, problem = _load_snapshot(args.snapshot)
    if snapshot is None:
        print(f"gcp-ground --hook: {problem} — nothing was checked (fail-open)",
              file=sys.stderr)
        return EXIT_OK
    # Requirements are resolved only once this event is genuinely being
    # grounded: an out-of-scope or non-policy event must stay byte-silent, so
    # the not-enforcing notice rides along with a real run, never with a skip.
    source = _requirements_source(args)
    rules, carried = _load_requirements(source, hook=True)
    report = ground_policy(path, snapshot, baseline=args.baseline, rules=rules)
    for verdict in carried:
        report.add(verdict)
    if args.explain:
        lines = _explain_lines(path, args.baseline)
        lines.extend(_sec_explain_lines(source, rules))
        print("\n".join(lines), file=sys.stderr)
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

    COMPILING NOTHING DOES NOT PASS. The walker never raises on a missing
    directory and returns an empty tuple, a report over zero verdicts is
    trivially ``ok`` and ``any`` over an empty sequence is False — so a renamed
    corpus directory used to exit 0 printing PASSED with every count zero and
    byte-empty stderr, in ``--check`` mode too, whose whole purpose is keeping
    committed artifacts honest. :func:`_compile_floor` turns "nothing was
    compiled" and "an artifact nobody's document produced" into explicit
    verdicts, and a DIR that is not a directory into a usage error, which is
    what exit 2 is reserved for.
    """
    snapshot, problem = _load_snapshot(args.snapshot)
    if snapshot is None:
        return _usage(problem, prog="compile-requirements")
    if not os.path.isdir(args.directory):
        # A regular file, and a path that is not there at all: both are the
        # operator naming the wrong thing, which is a usage error and not a
        # finding about any requirement. A CI job whose corpus directory was
        # renamed now fails here instead of passing over an empty walk.
        return _usage(f"{args.directory} is not a directory — there is no "
                      f"requirement corpus to compile", prog="compile-requirements")
    try:
        sec_compile = importlib.import_module("gcp_grounding.sec_compile")
        sec_parse = importlib.import_module("gcp_grounding.sec_parse")
    except ImportError as exc:
        return _usage(f"the requirements compiler is not available in this "
                      f"checkout ({exc})", prog="compile-requirements")
    _llm_note(args.llm, sec_compile)
    out_dir = args.out or os.path.join(args.directory, "compiled")
    try:
        results = sec_compile.compile_directory(
            args.directory, snapshot, out_dir=out_dir, check_only=args.check,
            independence=not args.no_independence)
    except OSError as exc:
        # An unwritable --out used to escape as a PermissionError traceback and
        # exit 1, colliding with the documented meaning of exit 1 (a rejected
        # promise). Where the artifacts go is a usage decision, so it reports as
        # one, on one line.
        return _usage(f"the artifacts could not be written to {out_dir} ({exc})",
                      prog="compile-requirements")
    # One report for the whole directory: a per-document render would make the
    # exit code and the printed evidence disagree about what "the compile" was.
    merged = GroundingReport(backend=get_solver().backend)
    for result in results:
        for verdict in result.report.verdicts:
            merged.add(verdict)
    for verdict in _compile_floor(sec_parse, args.directory, out_dir, results):
        merged.add(verdict)
    print(PolicyReport(merged, captured_at=snapshot.captured_at,
                       source=str(args.directory)).render(_FORMATS[args.format]))
    # ``_emit`` already records drift as a contradicted sec:artifact verdict, so
    # merged.ok covers it; the explicit check keeps the contract readable and
    # holds even if a future drift becomes verdict-free.
    drifted = any(result.drifted for result in results)
    return EXIT_OK if merged.ok and not drifted else EXIT_FAILED


#: The marker :func:`gcp_grounding.sec_compile._repo_relative` anchors a
#: recorded source path against. Named here rather than imported because the
#: compiler is resolved dynamically and may be absent from a checkout.
_REPO_MARKER = "pyproject.toml"


def _compile_floor(sec_parse: Any, directory: str, out_dir: str,
                   results) -> list[Verdict]:
    """The verdicts a compile owes about ITSELF, not about any one promise.

    Three of them, and none can be expressed as a promise status because each is
    about the set of documents rather than about a document:

    * NOTHING WAS COMPILED — no result at all, or every result yielded zero
      promises. A report over an empty verdict set passes, so without this the
      one mode that exists to keep committed artifacts honest is green forever
      on a corpus directory that no longer holds requirements.
    * AN ORPHAN ARTIFACT — a ``*.promises.json`` in *out_dir* that this compile
      did not produce, i.e. whose source document is gone. ``--check`` never
      looked at the directory listing, while
      :func:`gcp_grounding.sec_rules.load_directory` globs and loads exactly
      that file, so a deleted requirement kept being enforced with CI clean.
    * NO REPO ANCHOR — *directory* has no ``pyproject.toml`` ancestor, so
      ``_repo_relative`` falls back to a path relative to the CWD and the bytes
      of the artifact depend on where the compile ran from. That is an
      abstention, not a failure: the compile is honest, its recorded paths are
      merely not portable. RESIDUAL RISK, out of scope per the design's
      Non-goals and recorded as ESC-GX-SECCLI-001 — running ``--check`` from a
      different working directory than the compile still reports drift on a
      byte-identical corpus. Anchoring the recorded path to the corpus
      directory itself is what would close it.
    """
    verdicts: list[Verdict] = []
    compiled = sum(len(result.doc.promises) for result in results
                   if result.doc is not None)
    if not compiled:
        verdicts.append(Verdict(
            "ungrounded", "sec:compile", str(directory), 0,
            f"{directory}: nothing was compiled — no requirement document under "
            f"it yielded a promise, so this run checked nothing and a green exit "
            f"would mean only that there was nothing to look at"))
    expected = {f"{document.stem}.promises.json"
                for document in sec_parse.discover(directory)}
    for orphan in sorted(_artifact_names(out_dir) - expected):
        verdicts.append(Verdict(
            "ungrounded", "sec:compile", os.path.join(out_dir, orphan), 0,
            f"{orphan}: an orphan artifact — this compile did not produce it, so "
            f"the document it came from is gone while --requirements still loads "
            f"and enforces it; delete it or restore its source"))
    if _repo_anchor(directory) is None:
        verdicts.append(Verdict(
            "unverified", "sec:compile", str(directory), 0,
            f"{directory}: no {_REPO_MARKER} ancestor — the source path recorded "
            f"in each artifact is relative to the current working directory, so "
            f"--check reports drift when it runs from a different one "
            f"(ESC-GX-SECCLI-001)"))
    return verdicts


def _artifact_names(out_dir: str) -> set[str]:
    """The ``*.promises.json`` basenames already in *out_dir*.

    An unreadable or absent directory is an empty set, never a raise: this
    channel exists to ADD a finding, and it must not become a new way for the
    compile to crash.
    """
    try:
        return {name for name in os.listdir(out_dir)
                if name.endswith(".promises.json")}
    except OSError:
        logger.debug("the artifact directory %s could not be listed", out_dir,
                     exc_info=True)
        return set()


def _repo_anchor(directory: str) -> str | None:
    """The nearest ancestor of *directory* carrying :data:`_REPO_MARKER`."""
    current = os.path.abspath(directory)
    while True:
        if os.path.exists(os.path.join(current, _REPO_MARKER)):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


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
