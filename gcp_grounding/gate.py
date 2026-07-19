"""Changed-file gate: ground a diff's policy files against one snapshot.

:class:`PolicyGroundingGate` is the framework-agnostic integration surface
for CI and generator pipelines: configure it with a :class:`GcpSnapshot`
(or a snapshot JSON path), hand :meth:`~PolicyGroundingGate.check` a
changed-file set (e.g. the paths from a diff), and get back a
:class:`GateResult` — one :class:`FileResult` per changed file, an
aggregate ok/risk signal, and human-readable findings suitable for feeding
straight back into a generator's next prompt.

Which changed files get grounded:

- ``*.json`` (including ``*.policy.json`` and terraform-JSON ``*.tf.json``)
  is grounded end-to-end via :func:`gcp_grounding.preflight.ground_policy`,
  which auto-detects IAM policy / Org Policy / ``terraform show -json``
  plan content. A plain ``.json`` whose content is none of those (say a
  ``package.json``) is recorded ``unverified`` as a non-policy file and
  raises no risk.
- ``*.tf`` (raw HCL) is policy-relevant but not parseable offline by this
  gate; it is recorded ``unverified`` with a pointer at gating the
  ``terraform show -json`` plan output instead.
- Everything else is recorded ``unverified`` as a non-policy file.

**Fail-open contract:** :meth:`~PolicyGroundingGate.check` never raises on
its input. Unreadable files, invalid JSON, unrecognized shapes, and
non-policy files all land in an honest ``unverified`` file status —
``unverified`` never fails the gate, it only shows up in the ``risk``
signal when a *policy-relevant* file could not be judged.

The aggregate signal is two-part: ``GateResult.ok`` is the hard gate
(False iff some file has ungrounded/contradicted verdicts — deterministic
findings, likely hallucinations) and ``GateResult.risk`` grades the rest:
``"high"`` for hard findings, ``"low"`` when at least one policy-relevant
file went unjudged, ``"none"`` when everything checked out. As everywhere
in this package, ok means "these claims grounded against the snapshot",
never "the policy is safe" — intent is out of scope by design.

TODO(gcp-gate-wire): harness's pipeline would call this from its
orchestrator as a review-time gate — after a generator turn touches policy
files, run ``PolicyGroundingGate(snapshot).check(changed_files)`` over the
turn's diff, block the merge while ``result.ok`` is False, and feed
``result.findings()`` back into the generator's next prompt so a
hallucinated ``roles/bigquery.reader`` is corrected to the suggested
``roles/bigquery.dataViewer`` instead of shipping. The wire-up itself is
out of scope here.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Iterable

from .core.log import get_logger
from .core.report import GroundingReport, Verdict
from .core.solver import get_solver
from .knowledge import GcpSnapshot
from .preflight import detect_kind, ground_policy
from .report import PolicyReport

logger = get_logger(__name__)

__all__ = ["FILE_STATUSES", "RISK_LEVELS", "GATE_SCHEMA", "FileResult",
           "GateResult", "PolicyGroundingGate"]

#: Per-file outcome: "failed" = ungrounded/contradicted verdicts (fails the
#: gate); "unverified" = the gate could not judge the file (never fails it);
#: "ok" = everything decidable grounded.
FILE_STATUSES = ("ok", "unverified", "failed")

#: Aggregate risk: "high" = deterministic findings in some file; "low" = no
#: findings, but a policy-relevant file went unjudged; "none" = all clean.
RISK_LEVELS = ("none", "low", "high")

#: Version tag of :meth:`GateResult.to_dict`; breaking key changes bump it.
GATE_SCHEMA = "gcp-grounding-gate/1"

#: Suffixes that make a file a policy candidate by name alone; other
#: ``.json`` files qualify by content (their JSON sniffs as a policy kind).
_CANDIDATE_SUFFIXES = (".policy.json", ".tf.json")


@dataclass(frozen=True)
class FileResult:
    """One changed file's outcome: its status, whether the gate considered
    it policy-relevant, and the full per-file :class:`PolicyReport`."""

    path: str
    #: One of :data:`FILE_STATUSES`.
    status: str
    #: True when the gate treated the file as policy-relevant (by suffix or
    #: sniffed content) — only these raise :attr:`GateResult.risk` when
    #: unverified; a changed README never does.
    policy_candidate: bool
    report: PolicyReport

    @property
    def verdicts(self) -> tuple[Verdict, ...]:
        return tuple(self.report.report.verdicts)


@dataclass(frozen=True)
class GateResult:
    """The gate's structured answer for one changed-file set."""

    files: tuple[FileResult, ...]
    #: The snapshot's capture time — every verdict is only as fresh as this.
    captured_at: str
    #: Constraint-solver backend actually used ("z3" or "builtin").
    backend: str = "builtin"

    @property
    def ok(self) -> bool:
        """The hard gate: False iff some file failed (ungrounded or
        contradicted verdicts); ``unverified`` never fails it."""
        return all(f.status != "failed" for f in self.files)

    @property
    def risk(self) -> str:
        """One of :data:`RISK_LEVELS` — see the module docstring."""
        if any(f.status == "failed" for f in self.files):
            return "high"
        if any(f.policy_candidate and f.status == "unverified" for f in self.files):
            return "low"
        return "none"

    def counts(self) -> dict[str, int]:
        """File counts per status; every status key present even at zero."""
        return {s: sum(1 for f in self.files if f.status == s)
                for s in FILE_STATUSES}

    def findings(self) -> tuple[str, ...]:
        """Human-readable, path-prefixed findings for a generator's next
        prompt: every ungrounded/contradicted verdict (with did-you-mean
        suggestions inline), plus the unverified notes of policy-relevant
        files the gate could not judge at all — an unparseable
        ``*.policy.json`` is feedback too."""
        lines: list[str] = []
        for f in self.files:
            for v in f.verdicts:
                if v.status in ("ungrounded", "contradicted"):
                    tip = (f" (did you mean: {', '.join(v.suggestions)}?)"
                           if v.suggestions else "")
                    lines.append(f"{f.path}: {v.status} {v.kind} — {v.message}{tip}")
            if f.policy_candidate and f.status == "unverified":
                for v in f.verdicts:
                    lines.append(f"{f.path}: unverified — {v.message}")
        return tuple(lines)

    def render(self) -> str:
        """The whole gate result as human-readable text: one header line,
        then each file's :class:`PolicyReport` render, indented."""
        c = self.counts()
        lines = [
            f"GCP policy gate {'PASSED' if self.ok else 'FAILED'} "
            f"(risk: {self.risk}) [{self.backend}]  "
            f"files: {len(self.files)} — ok={c['ok']} "
            f"unverified={c['unverified']} failed={c['failed']}  "
            f"[snapshot {self.captured_at}]"
        ]
        if not self.files:
            lines.append("  (no changed files)")
        for f in self.files:
            lines.extend("  " + line for line in f.report.render("human").splitlines())
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """The machine document for CI, versioned by :data:`GATE_SCHEMA`."""
        return {
            "schema": GATE_SCHEMA,
            "ok": self.ok,
            "risk": self.risk,
            "backend": self.backend,
            "captured_at": self.captured_at,
            "counts": self.counts(),
            "files": [
                {
                    "path": f.path,
                    "status": f.status,
                    "policy_candidate": f.policy_candidate,
                    "report": f.report.to_dict(),
                }
                for f in self.files
            ],
            "findings": list(self.findings()),
        }


class PolicyGroundingGate:
    """The changed-file gate, configured once with the snapshot to ground
    against. Construction is strict (a broken snapshot is a setup error and
    raises); :meth:`check` is fail-open (bad *input* never raises)."""

    def __init__(self, snapshot: GcpSnapshot | str | os.PathLike[str]) -> None:
        if isinstance(snapshot, GcpSnapshot):
            self.snapshot = snapshot
        else:
            self.snapshot = GcpSnapshot.load(snapshot)

    def check(self, changed_files: Iterable[str | os.PathLike[str]]) -> GateResult:
        """Ground every policy-relevant file in *changed_files* (duplicates
        are processed once, order preserved) and aggregate the outcome.
        Callers should pass paths that exist — a deleted file surfaces as an
        unreadable one, i.e. ``unverified``."""
        backend = get_solver().backend
        results: list[FileResult] = []
        seen: set[str] = set()
        for raw in changed_files:
            path = os.fspath(raw)
            if path in seen:
                continue
            seen.add(path)
            results.append(self._check_one(path, backend))
        result = GateResult(files=tuple(results),
                            captured_at=self.snapshot.captured_at,
                            backend=backend)
        logger.debug("gate: %d file(s) → ok=%s risk=%s %s",
                     len(results), result.ok, result.risk, result.counts())
        return result

    # -- per-file ------------------------------------------------------------

    def _check_one(self, path: str, backend: str) -> FileResult:
        lower = path.lower()
        if lower.endswith(".tf"):
            return self._unverified(
                path, backend, candidate=True,
                note=f"{path}: raw Terraform HCL cannot be grounded offline — "
                     f"gate the `terraform show -json` plan output instead")
        if lower.endswith(".json"):
            if (lower.endswith(_CANDIDATE_SUFFIXES)
                    or self._sniffs_as_policy(path)):
                return self._file_result(path, self._ground(path, backend),
                                         candidate=True)
            return self._unverified(
                path, backend, candidate=False,
                note=f"{path}: not recognized as an IAM policy, Org Policy or "
                     f"terraform plan document — not checked")
        return self._unverified(
            path, backend, candidate=False,
            note=f"{path}: not a policy file (*.tf / *.json) — not checked")

    def _sniffs_as_policy(self, path: str) -> bool:
        """Whether a plain ``.json`` file's content looks like a policy
        document. Unreadable or invalid files sniff False — by name alone
        they were never policy-relevant."""
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            return False
        return detect_kind(doc) is not None

    def _ground(self, path: str, backend: str) -> GroundingReport:
        # ground_policy carries its own fail-open contract; the belt here is
        # for anything that still escapes (e.g. undecodable bytes), so the
        # gate's own never-crash promise doesn't ride on preflight's.
        try:
            return ground_policy(path, self.snapshot)
        except Exception as exc:
            logger.debug("fail-open: grounding crashed on %s", path, exc_info=True)
            report = GroundingReport()
            report.backend = backend
            report.add(Verdict(
                "unverified", "document", path, 0,
                f"{path}: grounding crashed ({type(exc).__name__}: {exc}) "
                f"— nothing was checked"))
            return report

    def _unverified(self, path: str, backend: str, candidate: bool,
                    note: str) -> FileResult:
        report = GroundingReport()
        report.backend = backend
        report.add(Verdict("unverified", "document", path, 0, note))
        return self._file_result(path, report, candidate)

    def _file_result(self, path: str, report: GroundingReport,
                     candidate: bool) -> FileResult:
        if not report.ok:
            status = "failed"
        elif report.verdicts and all(v.status == "unverified"
                                     for v in report.verdicts):
            status = "unverified"
        else:
            status = "ok"
        policy_report = PolicyReport(report, self.snapshot.captured_at,
                                     source=path)
        return FileResult(path=path, status=status,
                          policy_candidate=candidate, report=policy_report)
