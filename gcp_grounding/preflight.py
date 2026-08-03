"""End-to-end orchestration: one document in, one grounding report out.

:func:`ground_policy` is the gate's single entry point. It auto-detects what
kind of document it was handed (IAM allow/deny policy JSON, Org Policy JSON,
or ``terraform show -json`` plan output), extracts that kind's claims, runs
the Datalog existence reasoner and the constraint-solver layer, and merges
everything into one vendored
:class:`~gcp_grounding.core.report.GroundingReport`.

**Fail-open contract:** the gate never crashes on bad input. An unreadable
file, invalid JSON, an unrecognizable document shape, or a claim extractor
that chokes all record an honest ``unverified`` verdict and move on —
``unverified`` does not fail the gate (``report.ok`` only turns on
ungrounded/contradicted), so a document the gate cannot judge passes with
its ignorance on the record rather than blocking or, worse, silently
half-passing. That includes a recognized document whose content the
conservative extractors skipped entirely: zero claims from a non-empty
policy records an ``unverified`` verdict too (a legitimately empty IAM
allow policy — no bindings — is the one shape where zero claims is honest).

The ``terraform`` claim extractor (:mod:`gcp_grounding.tf_claims`) is looked
up dynamically: where the module is not present, a tf plan document yields a
single ``unverified`` verdict saying so instead of an import error. A claim
kind that no layer decides — no existence pass, no ``cel``/``constraint_value``
check, and no domain check registered in :mod:`gcp_grounding.registry` — lands
in ``unverified`` naming that gap, so every extracted claim still receives at
least one verdict (existence kinds such as ``resource_type_ref`` are decided by
the Datalog pass, not left unverified).

The optional *baseline* enables the z3 new⊆old policy comparison
(:func:`~gcp_grounding.constraints.check_policy_subset`); it is defined for
IAM policies only, and any other pairing is recorded as ``unverified``.
"""

from __future__ import annotations

import importlib
import json
import os
from typing import Any, Mapping

from . import registry
from .claims import iam_policy_claims, org_policy_claims
from .constraints import check_cel, check_constraint_value, check_policy_subset
from .core.log import get_logger
from .core.report import GroundingReport, Verdict
from .core.solver import get_solver
from .knowledge import GcpSnapshot
from .reasoner import EXISTENCE_KINDS, ground_existence
from .registry import CheckContext

logger = get_logger(__name__)

__all__ = ["DOCUMENT_KINDS", "detect_kind", "ground_policy"]

#: Document kinds :func:`detect_kind` can recognize. The two VPC Service
#: Controls kinds are decided by :mod:`gcp_grounding.vpcsc_claims` through the
#: registry once detected.
DOCUMENT_KINDS = ("iam_policy", "org_policy", "tf_plan",
                  "vpc_sc_perimeter", "access_level")

#: Top-level keys marking ``terraform show -json`` plan output.
_TF_PLAN_KEYS = ("format_version", "terraform_version", "planned_values",
                 "resource_changes")

#: Top-level keys marking a legacy-v1 Org Policy document.
_ORG_V1_KEYS = ("constraint", "booleanPolicy", "listPolicy")


def detect_kind(doc: Any) -> str | None:
    """Which of :data:`DOCUMENT_KINDS` *doc* looks like — or None.

    Checked most-distinctive first: tf plan markers, then the VPC Service
    Controls resource-named documents (which carry a ``spec`` block and would
    otherwise be misread as an Org Policy v2), then Org Policy (v1 typed-policy
    keys, or a v2 ``…/policies/<id>`` name / ``spec`` block), then an IAM
    policy's ``bindings`` (``etag`` + ``version`` alone also count: an empty
    IAM policy carries only those).
    """
    if not isinstance(doc, Mapping):
        return None
    if any(key in doc for key in _TF_PLAN_KEYS):
        return "tf_plan"
    name = doc.get("name")
    if isinstance(name, str):
        # An Access Context Manager resource name pins the VPC-SC kind before
        # the Org Policy `spec`-block sniff below claims it.
        if "/servicePerimeters/" in name:
            return "vpc_sc_perimeter"
        if "/accessLevels/" in name:
            return "access_level"
    if any(key in doc for key in _ORG_V1_KEYS):
        return "org_policy"
    if isinstance(name, str) and "/policies/" in name:
        return "org_policy"
    if isinstance(doc.get("spec"), Mapping):
        return "org_policy"
    if "bindings" in doc or ("etag" in doc and "version" in doc):
        return "iam_policy"
    return None


def ground_policy(path_or_obj: Any, snapshot: GcpSnapshot,
                  baseline: Any = None) -> GroundingReport:
    """Ground one policy document end-to-end against *snapshot*.

    *path_or_obj* is a JSON file path (``str``/``os.PathLike``) or an
    already-parsed document. *baseline* (same forms) opts into the new⊆old
    IAM-policy comparison. Never raises on bad input — see the module
    docstring's fail-open contract.
    """
    report = GroundingReport()
    solver = get_solver()
    report.backend = solver.backend

    doc, source, error = _load_document(path_or_obj)
    if error is not None:
        logger.debug("fail-open: %s: %s", source, error)
        report.add(Verdict("unverified", "document", source, 0,
                           f"{source}: {error} — nothing was checked"))
        if baseline is not None:
            report.add(Verdict("unverified", "subset", "iam-policy", 0,
                               f"{source}: {error} — new⊆old was not decided"))
        return report

    kind = detect_kind(doc)
    claims = _extract_claims(doc, kind, source, report)
    if (kind is not None and not claims and not report.verdicts
            and not _legitimately_empty(doc, kind)):
        # Zero-claims honesty: the document was recognized and carries
        # content, but the conservative extractor skipped all of it (e.g.
        # `bindings` as an object, a hybrid v1+v2 org policy). Silence here
        # would read as a clean pass — put the ignorance on the record.
        logger.debug("fail-open: %s: detected %s but extracted no claims",
                     source, kind)
        report.add(Verdict("unverified", "document", source, 0,
                           f"{source}: detected {kind} content, but nothing "
                           f"checkable could be extracted from it — nothing "
                           f"was checked"))

    # Baseline is parsed ONCE here and shared: CheckContext.baseline is the
    # PARSED document (not the path), so the registry pair checks and
    # _subset_verdict read it without re-loading. (sx-sec-preflight adds a
    # THIRD consumer of this same parsed baseline and must reuse this load
    # rather than re-reading the path.) An unreadable baseline abstains for a
    # stated reason below rather than letting a pair check silently see None.
    baseline_doc = baseline_kind = baseline_source = baseline_error = None
    if baseline is not None:
        baseline_doc, baseline_source, baseline_error = _load_document(baseline)
        if baseline_error is not None:
            baseline_doc = None
        else:
            baseline_kind = detect_kind(baseline_doc)

    ctx = CheckContext(snapshot=snapshot, solver=solver, document=doc,
                       document_kind=kind, source=source, claims=tuple(claims),
                       baseline=baseline_doc, baseline_kind=baseline_kind)

    existence = [c for c in claims if c.kind in EXISTENCE_KINDS]
    if existence:
        ground_existence(existence, snapshot, report)
    for claim in claims:
        # Every claim — existence kinds included — is offered to the registry;
        # the IAM escalation check, for one, attaches to `role`.
        registry_verdicts = registry.run_claim_checks(claim, ctx)
        for v in registry_verdicts:
            report.add(v)
        if claim.kind == "cel":
            report.add(check_cel(claim, solver))
        elif claim.kind == "constraint_value":
            report.add(check_constraint_value(claim, snapshot))
        elif (claim.kind not in EXISTENCE_KINDS and not registry_verdicts):
            report.add(Verdict("unverified", claim.kind, claim.value, 0,
                               f"{claim.location}: no offline check is wired for "
                               f"claim kind {claim.kind!r} — not decided"))

    for v in registry.run_document_checks(ctx):
        report.add(v)

    if baseline is not None:
        if baseline_error is not None:
            report.add(Verdict("unverified", "subset", "iam-policy", 0,
                               f"{baseline_source}: baseline {baseline_error} "
                               f"— new⊆old was not decided"))
        else:
            for v in _subset_verdict(doc, kind, solver, ctx, baseline_source):
                report.add(v)

    counts = report.counts()
    logger.debug("ground_policy(%s): kind=%s claims=%d verdicts=%s ok=%s",
                 source, kind, len(claims), counts, report.ok)
    return report


def _legitimately_empty(doc: Any, kind: str) -> bool:
    """Whether zero claims is the honest outcome for *doc*: an empty IAM
    allow policy (no ``bindings``, or ``bindings: []``) asserts nothing, so
    extracting nothing from it is not ignorance."""
    return (kind == "iam_policy" and isinstance(doc, Mapping)
            and doc.get("bindings", []) == [])


# -- document loading ---------------------------------------------------------


def _load_document(path_or_obj: Any) -> tuple[Any, str, str | None]:
    """→ (document, source label, error). Exactly one of document/error is
    meaningful; a parse or read failure is returned, never raised."""
    if not isinstance(path_or_obj, (str, os.PathLike)):
        return path_or_obj, "<policy object>", None
    source = os.fspath(path_or_obj)
    try:
        with open(path_or_obj, encoding="utf-8") as fh:
            return json.load(fh), source, None
    except OSError as exc:
        return None, source, f"the document could not be read ({exc})"
    except json.JSONDecodeError as exc:
        return None, source, f"the document is not valid JSON ({exc})"
    except (ValueError, RecursionError) as exc:
        # json.load also raises UnicodeDecodeError (a ValueError that is not
        # a JSONDecodeError) on non-UTF-8 bytes and RecursionError on deeply
        # nested JSON — both are bad input, not gate bugs, so they fail open.
        return None, source, (f"the document could not be parsed "
                              f"({type(exc).__name__}: {exc})")


# -- claim extraction (per detected kind, fail-open) --------------------------


def _extract_claims(doc: Any, kind: str | None, source: str,
                    report: GroundingReport) -> list[Any]:
    """The claims *doc* makes; extraction trouble becomes an ``unverified``
    verdict on *report* (fail-open), never an exception."""
    if kind is None:
        shape = (f"top-level keys {sorted(doc)}" if isinstance(doc, Mapping)
                 else f"top-level JSON is {type(doc).__name__}, not an object")
        report.add(Verdict("unverified", "document", source, 0,
                           f"{source}: document kind was not recognized ({shape}) "
                           f"— nothing was checked"))
        return []
    if kind == "tf_plan":
        extract = _tf_plan_extractor()
        if extract is None:
            report.add(Verdict("unverified", "document", source, 0,
                               f"{source}: detected a terraform plan, but the tf-plan "
                               f"claim extractor (gcp_grounding.tf_claims) is not "
                               f"available — its claims were not extracted"))
            return []
    elif kind == "iam_policy":
        extract = iam_policy_claims
    elif kind == "org_policy":
        extract = org_policy_claims
    else:
        # A document kind only a later domain module recognizes: its extractor
        # is registered in the registry, and degrades to an honest unverified
        # exactly like the tf-plan arm when that module is not installed.
        extract = registry.document_extractor(kind)
        if extract is None:
            report.add(Verdict("unverified", "document", source, 0,
                               f"{source}: detected {kind} content, but no claim "
                               f"extractor for document kind {kind!r} is available "
                               f"— its claims were not extracted"))
            return []
    try:
        return list(extract(doc))
    except Exception as exc:  # fail-open: never crash the gate on bad input
        logger.debug("fail-open: %s claim extraction failed for %s", kind, source,
                     exc_info=True)
        report.add(Verdict("unverified", "document", source, 0,
                           f"{source}: {kind} claim extraction failed ({exc}) "
                           f"— nothing was checked"))
        return []


def _tf_plan_extractor():
    """``tf_claims.terraform_plan_claims`` — or None where the module is not
    part of this checkout. Resolved dynamically so the gate degrades to an
    honest ``unverified`` instead of an import error."""
    try:
        module = importlib.import_module("gcp_grounding.tf_claims")
    except ImportError:
        return None
    return module.terraform_plan_claims


# -- baseline (new⊆old) comparison --------------------------------------------


def _subset_verdict(doc: Mapping[str, Any], kind: str | None, solver,
                    ctx: CheckContext, baseline_source: str) -> list[Verdict]:
    """The new⊆old verdict(s) for *doc* against the baseline already parsed on
    *ctx* — never re-reads the path.

    For IAM policies this is the z3 new⊆old comparison; for any other document
    kind a registered :data:`~gcp_grounding.registry.PAIR_CHECKS` widening check
    runs first, and only when there is none does the pairing record as an honest
    ``unverified``."""
    if kind != "iam_policy":
        pair = registry.pair_check(kind)
        if pair is not None:
            return registry.run_pair_check(pair, ctx)
        return [Verdict("unverified", "subset", "iam-policy", 0,
                        f"a baseline was given, but the document was detected as "
                        f"{kind or 'unrecognized'}, not an IAM policy — new⊆old "
                        f"was not decided")]
    if ctx.baseline_kind != "iam_policy":
        # A wrapped setIamPolicy body, an org policy, a deny policy: passing
        # it raw into check_policy_subset would read its absent `bindings` as
        # "grants nothing" and mint a false `contradicted`.
        return [Verdict("unverified", "subset", "iam-policy", 0,
                        f"{baseline_source}: the baseline's shape was not "
                        f"recognized as an IAM allow policy — new⊆old was not "
                        f"decided")]
    try:
        return [check_policy_subset(doc, ctx.baseline, solver)]
    except ValueError as exc:
        return [Verdict("unverified", "subset", "iam-policy", 0,
                        f"new⊆old was not decided: {exc}")]
