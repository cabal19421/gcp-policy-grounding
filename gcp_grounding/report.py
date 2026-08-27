"""Report adapter: policy-domain summary and rendering over the vendored core.

The vendored :mod:`gcp_grounding.core.report` is reused verbatim (reuse
contract: never edited): :class:`~gcp_grounding.core.report.GroundingReport`
already carries the four-bucket verdict model and the gate semantics — *ok*
iff nothing is ungrounded or contradicted. This module only wraps it with the
policy domain's presentation:

- :meth:`PolicyReport.summary` — the four-bucket counts, every status always
  present;
- a human renderer whose lines are anchored by the json-path locations the
  claim layer put in each message (policy documents have no line numbers, so
  the core renderer's ``path:lineno`` prefixes do not apply), stamping the
  snapshot's ``captured_at`` into every grounded/unverified line — those
  verdicts hold only as of the capture, while ungrounded messages already
  carry the stamp from the reasoner;
- :meth:`PolicyReport.to_dict` / ``render(format="json")`` — the machine
  document behind the CLI's ``--format json``, a stable schema for CI
  versioned by :data:`SCHEMA`.

A PASSED render means "these claims grounded against the snapshot", never
"the policy is safe" — intent is out of scope by design. And it says so on the
header line: an ok report with unverified verdicts is headlined ``PASSED
(<N> unchecked)``, and one in which NOTHING grounded at all is headlined
``PASSED — NOTHING VERIFIED (<N> unchecked)`` — approval from a report that
checked nothing must never read like approval from one that checked
everything. Only a fully decided report gets the bare word.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .core.log import get_logger
from .core.report import GroundingReport

logger = get_logger(__name__)

__all__ = ["FORMATS", "SCHEMA", "PolicyReport"]

#: Version tag of the JSON document; any breaking key change bumps it.
SCHEMA = "gcp-grounding-report/1"

#: Formats :meth:`PolicyReport.render` accepts; the CLI's ``--format`` flag
#: maps onto this.
FORMATS = ("human", "json")

#: Human-render order and mark per status: findings first, then the honest
#: leftovers, then what actually grounded. Unknown statuses are invisible
#: here (the core already warns when one is added) but still appear in the
#: JSON document.
_MARKS = (("contradicted", "⚠"), ("ungrounded", "✗"),
          ("unverified", "?"), ("grounded", "✓"))

#: Statuses whose lines carry the freshness stamp: "exists" and "undecidable
#: offline" are claims about the snapshot, true only as of its capture.
_STAMPED = ("grounded", "unverified")

#: The compile channel. A promise the compiler could not translate is recorded
#: on it AND on the promise's own domain channel, which is right for a consumer
#: reading either one and wrong for a reader, who gets the same sentence twice.
_COMPILE_KIND = "sec:compile"


def _compile_twins(verdicts) -> set[tuple[str, str, str]]:
    """The ``sec:<domain>`` verdicts a same-message :data:`_COMPILE_KIND`
    verdict already accounts for.

    RENDERING ONLY. :meth:`PolicyReport.to_dict` still carries both — the two
    channels exist so a consumer can filter on either — and the header counts
    are the four buckets over every verdict, unchanged. What is suppressed is
    the second PRINTED line of a sentence the reader has just read.
    """
    compiled = {(v.status, v.message) for v in verdicts
                if isinstance(v.kind, str) and v.kind == _COMPILE_KIND}
    if not compiled:
        return set()
    return {(v.status, v.kind, v.message) for v in verdicts
            if isinstance(v.kind, str) and v.kind.startswith("sec:")
            and v.kind != _COMPILE_KIND and (v.status, v.message) in compiled}


@dataclass(frozen=True)
class PolicyReport:
    """A policy-domain view over one vendored :class:`GroundingReport`."""

    report: GroundingReport
    #: ISO-8601 snapshot capture time (``GcpSnapshot.captured_at``).
    captured_at: str
    #: Optional label of the grounded document (e.g. its path), shown in the
    #: header and carried into the JSON document.
    source: str = ""

    def __post_init__(self) -> None:
        if not self.captured_at:
            raise ValueError("captured_at is required — grounded/unverified lines "
                             "are stamped with snapshot freshness")

    @property
    def ok(self) -> bool:
        """The gate, delegated: False iff anything is ungrounded or contradicted."""
        return self.report.ok

    def summary(self) -> dict[str, int]:
        """Four-bucket counts; every status key is present even at zero."""
        return self.report.counts()

    # -- rendering ------------------------------------------------------------

    def render(self, format: str = "human") -> str:
        """The report in one of :data:`FORMATS` (the CLI's ``--format``)."""
        if format == "human":
            return self._render_human()
        if format == "json":
            return self._render_json()
        raise ValueError(f"unknown format {format!r}; expected one of {FORMATS}")

    def to_dict(self) -> dict:
        """The machine document behind ``--format json``. Stable contract for
        CI: the top-level keys, their order, and the per-verdict keys only
        change together with a :data:`SCHEMA` bump."""
        return {
            "schema": SCHEMA,
            "ok": self.ok,
            "backend": self.report.backend,
            "captured_at": self.captured_at,
            "source": self.source,
            "summary": self.summary(),
            "verdicts": [
                {
                    "status": v.status,
                    "kind": v.kind,
                    "target": v.target,
                    "message": v.message,
                    "suggestions": list(v.suggestions),
                }
                for v in self.report.verdicts
            ],
        }

    def _render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def _headline(self, counts: dict[str, int]) -> str:
        """The header word, qualified by what was actually checked.

        ``FAILED`` is exact and unconditional — the hook's blocking path and
        its assertions key off that word. ``PASSED`` is exact only when every
        verdict was decided; an ok report carrying unverified verdicts says how
        many were not, and one in which nothing grounded at all says so in so
        many words: a document the gate could not judge a single claim of must
        not headline identically to one it verified in full.
        """
        if not self.ok:
            return "FAILED"
        unchecked = counts["unverified"]
        if not unchecked:
            return "PASSED"
        if counts["grounded"]:
            return f"PASSED ({unchecked} unchecked)"
        return f"PASSED — NOTHING VERIFIED ({unchecked} unchecked)"

    def _render_human(self) -> str:
        c = self.summary()
        subject = f" {self.source}" if self.source else ""
        lines = [
            f"GCP policy grounding{subject} {self._headline(c)} "
            f"[{self.report.backend}]  "
            f"grounded={c['grounded']} ungrounded={c['ungrounded']} "
            f"contradicted={c['contradicted']} unverified={c['unverified']}"
        ]
        twins = _compile_twins(self.report.verdicts)
        for status, mark in _MARKS:
            for v in self.report.by_status(status):
                if (v.status, v.kind, v.message) in twins:
                    continue
                stamp = f" [snapshot {self.captured_at}]" if status in _STAMPED else ""
                tip = f"  (did you mean: {', '.join(v.suggestions)}?)" if v.suggestions else ""
                lines.append(f"  {mark} [{v.kind}] {v.message}{stamp}{tip}")
        if not self.report.verdicts:
            lines.append("  (no claims to ground)")
        return "\n".join(lines)
