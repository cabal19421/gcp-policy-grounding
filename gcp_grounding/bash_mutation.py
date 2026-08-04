"""Curated classifier for state-mutating GCP CLI invocations found in shell text.

A pure, offline, dependency-free classifier: given a shell command string it
finds the segments that mutate GCP state via ``gcloud`` / ``gsutil`` / ``bq`` /
``terraform`` / ``terragrunt`` / ``kubectl`` or a ``curl``/``wget`` to a
``googleapis.com`` endpoint. It does NOT wire itself into any CLI — the module
is independently reviewable and unit-testable — and it never edits or depends on
mutable state in the vendored core (it only *reads* ``core.report.Verdict``).

The classifier is a leaf-verb generalization rather than an exhaustive command
table: it splits the command into segments, tokenizes each with :mod:`shlex`,
strips wrappers, and classifies by the last verb token. An unknown verb ABSTAINS
— it never blocks and never silently passes.

The four-bucket-honesty crux (read this before changing ``bash_mutation_verdicts``)
-----------------------------------------------------------------------------
A shell mutation is not a refuted grounding claim and not a hallucinated name;
the gate did not DECIDE anything about it, it was unable to look. So the status
of every emitted verdict is always ``"unverified"``, carried by two new
free-form kinds. A mutating finding gives::

    Verdict("unverified", "bash-mutation", finding.verb, 0,
            f"{finding.verb}: mutates GCP state directly, bypassing the "
            f"policy-document gate — nothing was grounded ({finding.detail})")

and an unrecognized finding gives::

    Verdict("unverified", "bash-unrecognized", finding.verb or "<command>", 0,
            f"{finding.detail} — not decided")

``Verdict.kind`` is the blessed extension point — free-form on the frozen core
dataclass — while adding a fifth STATUS is forbidden and would in any case be
invisible to ``report.ok``. The BLOCKING decision for mutating findings is a
policy choice made by the caller, deliberately NOT encoded as ``contradicted``,
so ``report.ok`` keeps failing only on ungrounded plus contradicted and the JSON
report never claims to have refuted something it merely could not see.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from gcp_grounding.core.report import Verdict

__all__ = [
    "MutationFinding",
    "scan_command",
    "bash_mutation_verdicts",
    "MUTATING_LEAF_VERBS",
    "READ_ONLY_LEAF_VERBS",
    "KNOWN_CLIS",
]


# -- vocabulary -------------------------------------------------------------

#: Leaf verbs that write GCP (or local terraform) state. Classification is by
#: the LAST verb token, so this covers the long tail without an exact table.
MUTATING_LEAF_VERBS = frozenset({
    "add-iam-policy-binding", "remove-iam-policy-binding", "set-iam-policy",
    "set-policy", "create", "update", "delete", "patch", "replace", "import",
    "apply", "enable", "disable", "enable-enforce", "disable-enforce", "allow",
    "deny", "undelete", "add-tag-binding", "remove-tag-binding", "reset", "ch",
    "set", "mb", "rb", "rm", "mv", "push", "taint", "untaint", "force-unlock",
    "destroy", "edit", "scale", "add-access", "remove-access",
})

#: Leaf verbs that only read. A leaf here produces NO finding.
READ_ONLY_LEAF_VERBS = frozenset({
    "list", "describe", "get", "get-iam-policy", "get-config", "help",
    "version", "info", "plan", "show", "validate", "fmt", "init", "output",
    "providers", "graph", "cat", "ls", "du", "stat", "diff",
})

#: The only argv[0] basenames this gate cares about; anything else is ordinary
#: shell and produces no finding (false positives here get the feature disabled).
KNOWN_CLIS = frozenset({
    "gcloud", "gsutil", "bq", "terraform", "terragrunt", "kubectl",
    "curl", "wget",
})

# Wrappers whose first real argument is the actual command.
_WRAPPERS = frozenset({"sudo", "env", "nohup", "time", "xargs"})

# A leading VAR=value environment assignment (stripped like a wrapper).
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# HTTP methods that write.
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_READ_METHODS = frozenset({"GET", "HEAD"})

# curl flags that carry a request body and therefore imply POST.
_DATA_FLAGS = frozenset({"-d", "--data", "--data-binary", "--data-raw", "--json"})
_DATA_EQ_PREFIXES = ("--data=", "--data-binary=", "--data-raw=", "--json=")

# Risk-flag evidence, scanned verbatim from the raw segment. Evidence never
# changes status — it is appended to the detail sentence as "flags seen: …".
_RISK_TOKENS = (
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "allUsers",
    "allAuthenticatedUsers",
    "0.0.0.0/0",
    "--impersonate-service-account",
    "--no-enforce",
)

# The one internal domain a --member value may name without being flagged.
_INTERNAL_MEMBER_DOMAIN = "acme.example"

_SEGMENT_MAX = 200


# -- the finding ------------------------------------------------------------


@dataclass(frozen=True)
class MutationFinding:
    """One classified shell segment.

    ``status`` is ``"mutating"`` or ``"unrecognized"``; a benign (read-only or
    non-GCP) shape produces no finding at all. ``cli`` is the recognized tool
    (empty when the segment could not even be tokenized). ``verb`` is the
    normalized invocation shape, e.g. ``"gcloud projects add-iam-policy-binding"``.
    ``detail`` is one human sentence including any risk-flag evidence found.
    ``segment`` is the raw shell segment, truncated to 200 chars.
    """

    status: str
    cli: str
    verb: str
    detail: str
    segment: str


# -- public entry points ----------------------------------------------------


def scan_command(command: str) -> list[MutationFinding]:
    """Classify every mutating/unrecognized shell segment in *command*.

    Deterministic, ordered by shell-segment position, and never raises.
    """
    findings: list[MutationFinding] = []
    if not isinstance(command, str):
        return findings
    for segment in _split_segments(command):
        try:
            finding = _scan_segment(segment)
        except Exception:  # pragma: no cover - defensive: scan_command never raises
            finding = None
        if finding is not None:
            findings.append(finding)
    return findings


def bash_mutation_verdicts(command: str, *, source: str = "Bash") -> list[Verdict]:
    """Emit one honest ``unverified`` Verdict per finding (see module docstring).

    *source* is accepted for caller context and API stability; the verdict
    messages are the fixed strings the honesty contract pins, so it is
    intentionally not woven into them.
    """
    del source  # reserved; the pinned messages must stay byte-stable
    verdicts: list[Verdict] = []
    for finding in scan_command(command):
        if finding.status == "mutating":
            verdicts.append(Verdict(
                "unverified", "bash-mutation", finding.verb, 0,
                f"{finding.verb}: mutates GCP state directly, bypassing the "
                f"policy-document gate — nothing was grounded ({finding.detail})"))
        else:
            verdicts.append(Verdict(
                "unverified", "bash-unrecognized", finding.verb or "<command>", 0,
                f"{finding.detail} — not decided"))
    return verdicts


# -- step 1: conservative segment split -------------------------------------


def _split_segments(command: str) -> list[str]:
    """Split on ``;``, ``&&``, ``||``, ``|`` and newline, ignoring separators
    inside single or double quotes. A conservative char scanner, not a shell
    parser: escapes are not interpreted, which can only over-quote (never
    silently drop a mutation, since each segment is re-tokenized honestly)."""
    segments: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(command)
    while i < n:
        c = command[i]
        if in_single:
            buf.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            buf.append(c)
            if c == '"':
                in_double = False
            i += 1
            continue
        if c == "'":
            in_single = True
            buf.append(c)
            i += 1
            continue
        if c == '"':
            in_double = True
            buf.append(c)
            i += 1
            continue
        if c == "&" and i + 1 < n and command[i + 1] == "&":
            segments.append("".join(buf))
            buf = []
            i += 2
            continue
        if c == "|" and i + 1 < n and command[i + 1] == "|":
            segments.append("".join(buf))
            buf = []
            i += 2
            continue
        if c in ";|\n":
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    segments.append("".join(buf))
    return segments


# -- steps 2-8: per-segment classification ----------------------------------


def _scan_segment(segment: str) -> MutationFinding | None:
    if not segment.strip():
        return None
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        # step 2: unbalanced quotes — abstain, do not guess.
        return MutationFinding(
            "unrecognized", "", "",
            "the command could not be tokenized — not decided",
            _truncate(segment))
    if not tokens:
        return None
    # step 3: strip leading VAR=value assignments and sudo/env/nohup/time/xargs.
    argv = _strip_wrappers(tokens)
    if not argv:
        return None
    cli = _basename(argv[0])
    if cli not in KNOWN_CLIS:
        return None  # ordinary shell command — not this gate's business
    if cli in ("curl", "wget"):
        return _scan_http(cli, argv, tokens, segment)
    return _scan_cli(cli, argv, tokens, segment)


def _strip_wrappers(tokens: list[str]) -> list[str]:
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if _ASSIGN.match(tok):
            i += 1
            continue
        if _basename(tok) in _WRAPPERS:
            i += 1
            continue
        break
    return tokens[i:]


def _scan_cli(cli: str, argv: list[str], tokens: list[str],
              segment: str) -> MutationFinding | None:
    # step 4: the verb path is the leading tokens (after argv[0]) that do not
    # start with a hyphen; we stop at the first recognized leaf verb so a
    # positional resource name is never mistaken for the verb.
    leading: list[str] = []
    for tok in argv[1:]:
        if tok.startswith("-"):
            break
        leading.append(tok)
    if not leading:
        return None  # bare `gcloud`, `gcloud --help`, … — nothing to classify

    path_tokens = leading
    leaf = leading[-1]
    for idx, tok in enumerate(leading):
        if tok in MUTATING_LEAF_VERBS or tok in READ_ONLY_LEAF_VERBS:
            path_tokens = leading[:idx + 1]
            leaf = tok
            break

    verb = f"{cli} {' '.join(path_tokens)}"

    # step 5: classify by the leaf verb.
    if leaf in READ_ONLY_LEAF_VERBS:
        return None
    if leaf in MUTATING_LEAF_VERBS:
        base = f"{verb} is a state-mutating invocation"
        detail = _with_evidence(base, cli, tokens, segment)
        return MutationFinding("mutating", cli, verb, detail, _truncate(segment))
    # an unknown verb ABSTAINS — name it verbatim, never block, never pass.
    base = f"{verb!r} is not a recognized mutating or read-only verb"
    detail = _with_evidence(base, cli, tokens, segment)
    return MutationFinding("unrecognized", cli, verb, detail, _truncate(segment))


def _scan_http(cli: str, argv: list[str], tokens: list[str],
               segment: str) -> MutationFinding | None:
    # step 6: curl/wget matter only when they touch a googleapis.com host.
    if "googleapis.com" not in segment:
        return None
    method = None
    data_flag = False
    rest = argv[1:]
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in ("-X", "--request"):
            if i + 1 < len(rest):
                method = rest[i + 1].upper()
            i += 2
            continue
        if tok.startswith("--request="):
            method = tok.split("=", 1)[1].upper()
            i += 1
            continue
        if tok.startswith("-X") and len(tok) > 2:
            method = tok[2:].upper()
            i += 1
            continue
        if tok in _DATA_FLAGS or tok.startswith(_DATA_EQ_PREFIXES):
            data_flag = True
            i += 1
            continue
        if tok.startswith("-d") and len(tok) > 2:
            data_flag = True
            i += 1
            continue
        i += 1

    if data_flag or method in _MUTATING_METHODS:
        effective = method if method in _MUTATING_METHODS else "POST"
        verb = f"{cli} {effective}"
        base = f"an HTTP {effective} to a googleapis.com endpoint"
        detail = _with_evidence(base, cli, tokens, segment)
        return MutationFinding("mutating", cli, verb, detail, _truncate(segment))
    if method is None or method in _READ_METHODS:
        return None  # a plain GET to googleapis.com produces no finding
    # some other explicit method whose effect we cannot judge — abstain.
    verb = f"{cli} {method}"
    base = f"an HTTP {method} to a googleapis.com endpoint of unclear effect"
    detail = _with_evidence(base, cli, tokens, segment)
    return MutationFinding("unrecognized", cli, verb, detail, _truncate(segment))


# -- step 8: risk evidence (never changes status) ---------------------------


def _with_evidence(base: str, cli: str, tokens: list[str], segment: str) -> str:
    evidence = _collect_evidence(cli, tokens, segment)
    if evidence:
        return f"{base}; flags seen: " + ", ".join(evidence)
    return base


def _collect_evidence(cli: str, tokens: list[str], segment: str) -> list[str]:
    seen: list[str] = []
    for token in _RISK_TOKENS:
        if token in segment and token not in seen:
            seen.append(token)
    for member in _external_members(tokens):
        if member not in seen:
            seen.append(member)
    # step 7: terraform/terragrunt -auto-approve is evidence too.
    if cli in ("terraform", "terragrunt") and "-auto-approve" in tokens:
        if "-auto-approve" not in seen:
            seen.append("-auto-approve")
    return seen


def _external_members(tokens: list[str]) -> list[str]:
    """--member (or --members) values whose domain is not the internal one."""
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        value = None
        if tok in ("--member", "--members") and i + 1 < len(tokens):
            value = tokens[i + 1]
        elif tok.startswith("--member=") or tok.startswith("--members="):
            value = tok.split("=", 1)[1]
        if value and "@" in value:
            domain = value.rsplit("@", 1)[-1]
            if domain != _INTERNAL_MEMBER_DOMAIN:
                out.append(value)
        i += 1
    return out


# -- small helpers ----------------------------------------------------------


def _basename(token: str) -> str:
    return token.rsplit("/", 1)[-1]


def _truncate(segment: str) -> str:
    return segment.strip()[:_SEGMENT_MAX]
