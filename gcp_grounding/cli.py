"""Command-line interface: ``gcp-ground verify-policy``.

One subcommand over the preflight gate
(:func:`~gcp_grounding.preflight.ground_policy`), exposed both as the
``gcp-ground`` console script and as ``python -m gcp_grounding``::

    gcp-ground verify-policy FILE [--snapshot PATH] [--baseline PATH]
                             [--format text|json] [--explain] [--hook]

Exit codes carry the gate's honesty contract:

- ``0`` — the gate passed: every claim grounded *or* was honestly
  ``unverified`` (fail-open — ignorance never fails the gate);
- ``1`` — something is ungrounded or contradicted;
- ``2`` — the invocation itself is unusable (bad flags, no snapshot), or, in
  ``--hook`` mode, the gate found ungrounded/contradicted claims — ``2`` is
  the Claude-Code blocking exit code, and the findings go to stderr so the
  hook runner feeds them back to the agent.

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

``--explain`` re-derives and dumps (to stderr, keeping stdout parseable for
``--format json``) the z3 constraints this run generated: the translated
formula per ``cel`` condition and the new⊈old satisfiability assertion when
a ``--baseline`` comparison ran. The derivation is deterministic, so the
re-generated formulas are exactly the ones the checks decided.

stdlib ``argparse`` only — no third-party CLI framework.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from typing import Any, Mapping

from .claims import iam_policy_claims, org_policy_claims
# Explain reuses the constraint layer's own encoders (private to the package,
# not the world) — re-implementing the CEL translation here would let the
# dumped formulas drift from the ones actually decided.
from .constraints import UnsupportedCel, _CelToZ3, _grant_pairs, _Undecidable, _z3_module
from .core.log import get_logger
from .core.solver import get_solver
from .knowledge import GcpSnapshot
from .preflight import detect_kind, ground_policy
from .report import PolicyReport

logger = get_logger(__name__)

__all__ = ["SNAPSHOT_ENV", "build_parser", "main"]

#: Environment variable consulted when ``--snapshot`` is not given.
SNAPSHOT_ENV = "GCP_GROUNDING_SNAPSHOT"

#: CLI ``--format`` values → :meth:`PolicyReport.render` formats.
_FORMATS = {"text": "human", "json": "json"}

#: File suffixes ``--hook`` treats as policy documents worth grounding.
_HOOK_SUFFIXES = (".tf", ".json")

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
    verify.set_defaults(handler=_cmd_verify_policy)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


# -- verify-policy ------------------------------------------------------------


def _cmd_verify_policy(args: argparse.Namespace) -> int:
    if args.hook:
        if args.file is not None:
            return _usage("FILE and --hook are mutually exclusive — the hook "
                          "event names the edited file")
        return _run_hook(args)
    if args.file is None:
        return _usage("FILE is required (only --hook mode reads the file from "
                      "a PostToolUse event instead)")
    snapshot, problem = _load_snapshot(args.snapshot)
    if snapshot is None:
        return _usage(problem)
    report = ground_policy(args.file, snapshot, baseline=args.baseline)
    rendered = PolicyReport(report, captured_at=snapshot.captured_at,
                            source=args.file).render(_FORMATS[args.format])
    print(rendered)
    if args.explain:
        print("\n".join(_explain_lines(args.file, args.baseline)), file=sys.stderr)
    return EXIT_OK if report.ok else EXIT_FAILED


def _usage(problem: str) -> int:
    print(f"gcp-ground verify-policy: error: {problem}", file=sys.stderr)
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


# -- --hook: Claude-Code PostToolUse ------------------------------------------


def _run_hook(args: argparse.Namespace) -> int:
    """Ground the file a PostToolUse event says was edited. Fail-open: only
    a real ungrounded/contradicted finding exits nonzero."""
    path = _hook_file_path(_read_hook_event(sys.stdin))
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
    report = ground_policy(path, snapshot, baseline=args.baseline)
    if args.explain:
        print("\n".join(_explain_lines(path, args.baseline)), file=sys.stderr)
    if report.ok:
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


def _hook_file_path(event: Mapping[str, Any] | None) -> str | None:
    if event is None:
        return None
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, Mapping):
        return None
    path = tool_input.get("file_path")
    return path if isinstance(path, str) and path else None


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

    def granted(pairs):
        if not pairs:
            return z3.BoolVal(False)
        return z3.Or([z3.And(role == z3.StringVal(r), member == z3.StringVal(m))
                      for r, m in sorted(pairs)])

    assertion = z3.And(granted(new_grants), z3.Not(granted(old_grants)))
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
