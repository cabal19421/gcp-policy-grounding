"""Changed-file gate: ground a diff's policy files against the three inputs.

:class:`PolicyGroundingGate` is the framework-agnostic integration surface
for CI and generator pipelines: configure it with a :class:`GcpSnapshot`
(or a snapshot JSON path), hand :meth:`~PolicyGroundingGate.check` a
changed-file set (e.g. the paths from a diff), and get back a
:class:`GateResult` — one :class:`FileResult` per changed file, an
aggregate ok/risk signal, and human-readable findings suitable for feeding
straight back into a generator's next prompt.

THE THREE INPUTS, and what each changed file is judged against:

- the PROPOSAL is the changed file itself, routed by suffix. FOUR suffixes
  are policy candidates by name alone, and when an agent edits terraform the
  proposal IS the terraform:

  ``*.policy.json`` and every other ``*.json``
      read end-to-end, auto-detecting IAM policy / Org Policy /
      ``terraform show -json`` plan content. A plain ``.json`` whose content
      is none of those (say a ``package.json``) is recorded ``unverified``
      as a non-policy file and raises no risk.
  ``*.tf.json``
      TERRAFORM'S OWN JSON CONFIGURATION SYNTAX, parsed with ``json.load``
      and no parser at all. Both legal ``resource`` encodings — a mapping of
      type to name to body, and a list of single-key mappings — are walked
      to the same ``type.name`` addresses, interpolations are stripped and
      REPORTED, and the blocks are assembled into one synthetic plan
      document so ``tf_claims.terraform_plan_claims`` and every registered
      provider extractor apply unchanged.
  ``*.tf``
      RAW HCL, read through :mod:`gcp_grounding.tfsource.hcl` (resolved
      lazily, so a checkout without the reader degrades to a stated note)
      and fed through the SAME assemble-then-prepare pipeline as
      ``*.tf.json``. A static read of a terraform program enumerates a
      SUBSET of what will be applied, so the file always carries one
      unresolved path and no ``grounded`` on it is ever claimed clean;
      ``ungrounded`` and ``contradicted`` findings stand and still block.
  ``*.tfstate``
      NOT A PROPOSAL, EVER. State describes what EXISTS, so grading it would
      report the whole estate as if an agent had just written it. It is
      recorded ``unverified`` with
      :data:`gcp_grounding.tfsource.discover.STATE_NOT_A_PROPOSAL` — the
      shared constant, so this entry point and the CLI cannot say different
      things about the same file — and pointed at the terraform-state flag
      and the config file as the way to use it as a BASELINE. An
      extensionless or plain-``.json`` state file reaches the same arm
      through :func:`gcp_grounding.tfsource.discover.is_v4_state`, applied
      BEFORE the kind detector.

  Everything else is recorded ``unverified`` as a non-policy file.
- the CURRENT state is the ``current`` constructor argument, the sources a
  ``resolve_sources`` construction assembled, or — with ``discover_config``
  — the state discovered PER EDITED FILE by walking up from that file. It
  is what supplies each proposal's baseline, and therefore what makes the
  pair checks reachable at all from the agentic path: a hook command line
  is one fixed string and can pin exactly ONE baseline for a whole session,
  while an agent editing three modules needs three different counterparts.
- the RULES are the built-in claim/document/pair checks plus the compiled
  ``sec_requirements`` promises named by the per-file discovered settings.

With NO current-state configuration the gate behaves exactly as it always
has: every candidate file is grounded with the plain snapshot and no
baseline, the result dict is byte-identical key for key, and none of the
machinery below is even imported. Every new behaviour is gated on a
configured source.

**Fail-open contract:** :meth:`~PolicyGroundingGate.check` never raises on
its input. Unreadable files, invalid JSON, unrecognized shapes, and
non-policy files all land in an honest ``unverified`` file status —
``unverified`` never fails the gate, it only shows up in the ``risk``
signal when a *policy-relevant* file could not be judged.

The aggregate signal is two-part: ``GateResult.ok`` is the hard gate
(False iff some file has ungrounded/contradicted verdicts — deterministic
findings, likely hallucinations) and ``GateResult.risk`` grades the rest:
``"high"`` for hard findings, ``"low"`` when at least one policy-relevant
file went unjudged or carries an :data:`ALWAYS_REPORT_KINDS` verdict,
``"none"`` when everything checked out. As everywhere in this package, ok
means "these claims grounded against the snapshot", never "the policy is
safe" — intent is out of scope by design.
"""

from __future__ import annotations

import dataclasses
import importlib
import json
import os
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from . import preflight
from .core.log import get_logger
from .core.report import GroundingReport, Verdict
from .core.solver import get_solver
from .knowledge import GcpSnapshot
from .preflight import detect_kind, ground_policy
from .report import PolicyReport

logger = get_logger(__name__)

__all__ = ["FILE_STATUSES", "RISK_LEVELS", "GATE_SCHEMA", "ALWAYS_REPORT_KINDS",
           "FileResult", "GateResult", "PolicyGroundingGate",
           "TerraformProposal", "terraform_route", "terraform_proposal"]

#: Per-file outcome: "failed" = ungrounded/contradicted verdicts (fails the
#: gate); "unverified" = the gate could not judge the file (never fails it);
#: "ok" = everything decidable grounded.
FILE_STATUSES = ("ok", "unverified", "failed")

#: Aggregate risk: "high" = deterministic findings in some file; "low" = no
#: findings, but a policy-relevant file went unjudged or carries an
#: always-reported verdict; "none" = all clean.
RISK_LEVELS = ("none", "low", "high")

#: Version tag of :meth:`GateResult.to_dict`; breaking key changes bump it.
#: It is deliberately NOT bumped by the current-state input: the only key the
#: document gains — ``state`` — appears exactly when a state source was
#: CONFIGURED, so a consumer pinned to this string that configures nothing
#: receives a byte-identical document, key set included.
GATE_SCHEMA = "gcp-grounding-gate/1"

#: Verdict kinds surfaced in :meth:`GateResult.findings` REGARDLESS of the
#: file's own status. Without this, a file with one ``ok`` verdict and one
#: drift verdict shows the agent nothing at all — the unverified pass only
#: fires when the WHOLE file is unverified — and drift is invisible on
#: exactly the path it matters on.
#:
#: THIS TUPLE AND :data:`gcp_grounding.drift.MAX_DRIFT_VERDICTS` ARE TWO
#: HALVES OF ONE PROMISE and must be read together. A naive head-truncation
#: of a capped drift list can drop the very verdict this tuple guarantees will
#: always show, which is why ``drift.py`` fills its budget ROUND-ROBIN over
#: ``drift.DRIFT_KINDS`` and never drops the first verdict of any kind. Assert
#: the pair, never either half alone.
#:
#: Everything here is ``unverified``, so the overall ok flag is untouched and
#: a drift never fails the gate by itself — but the agent and the operator
#: both see it.
ALWAYS_REPORT_KINDS = (
    "drift",
    "drift:material",
    "drift:unmanaged",
    "drift:unmergeable",
    "drift:verdict",
    "drift:key-mismatch",
    "state:source",
    "state:no-snapshot",
    "baseline:target",
    "baseline:unqueried",
    "baseline:new",
    "baseline:stale",
    "baseline:opaque",
    "baseline:ambiguous",
    "baseline:key-mismatch",
    "proposal:unresolved",
    "estate:incomplete",
    "engine:crashed",
)

#: Suffixes that make a file a policy candidate by name alone; other
#: ``.json`` files qualify by content (their JSON sniffs as a policy kind, or
#: as terraform state). Matched case-insensitively, and ``.tf.json`` is tested
#: BEFORE ``.tf`` and ``.json`` everywhere, since it ends with both.
_CANDIDATE_SUFFIXES = (".policy.json", ".tf.json", ".tf", ".tfstate")

#: :data:`gcp_grounding.engine.UNRESOLVED_KIND`, spelled here so the raw-``.tf``
#: note can carry it without importing the engine. It is in
#: :data:`ALWAYS_REPORT_KINDS`, so the note reaches the agent whatever the
#: file's own status turns out to be.
_UNRESOLVED_KIND = "proposal:unresolved"

#: Terraform's JSON spelling of a comment, legal at every level of a
#: ``.tf.json`` document and never an attribute.
_COMMENT_KEY = "//"

#: The two terraform CONFIGURATION suffixes — the ones that are a PROPOSAL.
#: ``.tfstate`` is deliberately not here: state is never a proposal.
_TERRAFORM_SUFFIXES = (".tf.json", ".tf")

#: The ``facts.PROPOSED_SOURCES`` spelling for configuration read as a proposed
#: change, mirroring :data:`gcp_grounding.tfsource.hcl.PROPOSED_SOURCE`. Spelled
#: literally so the ``.tf.json`` arm needs no parser and no ``tfsource`` import.
_HCL_PROPOSED = "hcl-proposed"

#: The one unresolved path a raw ``.tf`` ALWAYS reports, and why it always
#: does. Terraform configuration is a PROGRAM: variables, locals, function
#: calls, ``module`` blocks and the other ``.tf`` files of the same module are
#: not evaluated by a static reader, so what was enumerated is a SUBSET of what
#: terraform will apply. Reporting it is what makes the engine downgrade every
#: ``grounded`` on the file to ``unverified`` — a resource whose rule set may be
#: truncated must never produce a conclusion that no permissive rule exists.
#: ``ungrounded`` and ``contradicted`` STAND, so a hallucinated role name in raw
#: HCL still fails the gate.
_HCL_SUBSET_PATH = "{path}:<hcl-static-read>"

#: The terraform note the gate emits for a raw ``.tf`` it DID read.
_HCL_READ_NOTE = (
    "{path}: raw Terraform HCL was read STATICALLY — variables, locals, "
    "function calls, `module` blocks and the other files of this module are "
    "not evaluated, so what was enumerated is a SUBSET of what terraform will "
    "apply and nothing on this file is reported as a clean pass. Gate the "
    "`terraform show -json` plan output, or the equivalent .tf.json, for a "
    "complete view. Terraform-derived ESTATE facts come from the "
    "terraform-state and merge-source flags, never from the file under review."
)

#: The same note for a checkout WITHOUT the HCL reader — still unverified,
#: still a policy candidate.
_HCL_ABSENT_NOTE = (
    "{path}: raw Terraform HCL was NOT parsed, because the HCL reader "
    "gcp_grounding.tfsource.hcl is not available in this checkout. Gate the "
    "`terraform show -json` plan output, or the equivalent .tf.json, instead. "
    "Terraform-derived ESTATE facts come from the terraform-state and "
    "merge-source flags, never from the file under review."
)

#: The same, for a checkout whose terraform PROPOSAL machinery is incomplete.
_TF_ENGINE_ABSENT_NOTE = (
    "{path}: terraform configuration was not graded, because {missing} "
    "is not part of this checkout — gate the `terraform show -json` plan "
    "output instead."
)

#: A DUPLICATE OF LAST RESORT, used only where ``tfsource`` cannot be imported.
#: :data:`gcp_grounding.tfsource.discover.STATE_NOT_A_PROPOSAL` is
#: AUTHORITATIVE and is what every reachable checkout emits; this copy exists
#: so a stripped checkout still refuses to grade a state file, and it is
#: byte-identical on purpose — a differently WORDED copy is exactly the drift
#: the shared constant exists to prevent.
_STATE_NOT_A_PROPOSAL_FALLBACK = (
    "{path}: this is Terraform state, not a proposed change. State records "
    "what already EXISTS, so it is a CURRENT-state source; it was not graded "
    "as a proposal, because grading it would report the whole estate as if an "
    "agent had just written it. Pass it with the terraform-state flag, or "
    "list it as a state source in the config file, to use it as a baseline "
    "for other edits."
)

#: Appended when the state file under review is ALREADY one of this run's
#: configured state sources — the user is looking at the baseline itself.
_ALREADY_A_STATE_SOURCE = (
    " It is already configured as a state source for this run, so the facts "
    "in it are already part of the current state every other edited file was "
    "compared against."
)

#: The blocks of :func:`gcp_grounding.explain_state.state_document` carried
#: onto a file result, in document order.
_STATE_BLOCKS = ("sources", "settings", "targets", "drift")

#: ``check(as_of=...)`` omitted — DISTINCT from an explicit ``None``, which is
#: the documented way to say the run pins no clock.
_OMITTED: Any = object()


def _optional(name: str) -> Any:
    """``gcp_grounding.<name>``, or ``None`` where it is not part of this
    checkout.

    The try-import-except-``ImportError`` idiom :mod:`gcp_grounding.preflight`
    already uses for ``tf_claims`` and ``sec_rules``, applied to every module
    the current-state input needs. A checkout without them keeps this gate
    byte-identical, because nothing here is imported until a source is
    configured.
    """
    try:
        return importlib.import_module(f"{__package__}.{name}")
    except ImportError:
        logger.debug("gcp_grounding.%s is not part of this checkout", name)
        return None


def _tf_module(name: str) -> Any:
    """``gcp_grounding.tfsource.<name>``, or ``None`` where the terraform
    readers are not part of this checkout.

    The same try-import-except-``ImportError`` idiom as :func:`_optional`, and
    the same lazy-extractor precedent :mod:`gcp_grounding.preflight` sets: the
    import happens INSIDE the call, so a checkout without the ``tfsource``
    subpackage degrades to a stated note rather than failing to import the
    gate. That path stays live code even though the readers now ship.
    """
    try:
        return importlib.import_module(f"{__package__}.tfsource.{name}")
    except ImportError:
        logger.debug("gcp_grounding.tfsource.%s is not part of this checkout", name)
        return None


def _is_v4_state(document: Any) -> bool:
    """Whether *document* is a version-4 Terraform state file.

    THE ONE PREDICATE, resolved lazily:
    :func:`gcp_grounding.tfsource.discover.is_v4_state` is authoritative and is
    what decides this everywhere it can be imported. ``tx-cli-state-flags``
    applies the same sniff to the ``verify-policy`` positional argument and
    ``tx-tf-discover``'s ``tfstate`` arm applies it again on classification;
    three hand-written ``version == 4`` tests would be three places to drift,
    and a drifted sniff is exactly the zero-claim clean pass this arm exists to
    close.
    """
    discover = _tf_module("discover")
    if discover is not None:
        return bool(discover.is_v4_state(document))
    # A DUPLICATE OF LAST RESORT, for the import-unavailable path ONLY.
    # `discover.is_v4_state` is AUTHORITATIVE; this exists so a checkout
    # without `tfsource` still refuses to grade a state file as a proposal.
    return (isinstance(document, Mapping)
            and document.get("version") == 4
            and "lineage" in document
            and isinstance(document.get("resources"), list))


# -- terraform's own JSON configuration syntax --------------------------------


def _tf_json_entries(document: Any) -> list[tuple[str, str, Mapping[str, Any]]]:
    """``(type, name, body)`` for BOTH legal ``resource`` encodings.

    A MAPPING of type to name to body, and a LIST of single-key mappings of the
    same shape — both are committed as fixtures, so neither is hypothetical.
    The innermost value may itself be a one-element LIST of blocks, which is
    the array spelling of a body. Anything else is skipped rather than guessed
    at, and ``"//"`` comment keys are dropped at every level.
    """
    block = document.get("resource") if isinstance(document, Mapping) else None
    containers = [block] if isinstance(block, Mapping) else (
        [entry for entry in block if isinstance(entry, Mapping)]
        if isinstance(block, list) else [])
    entries: list[tuple[str, str, Mapping[str, Any]]] = []
    for container in containers:
        for resource_type, named in container.items():
            if resource_type == _COMMENT_KEY or not isinstance(named, Mapping):
                continue
            for name, body in named.items():
                if name == _COMMENT_KEY:
                    continue
                if isinstance(body, list) and len(body) == 1:
                    body = body[0]      # the one-element array spelling of a body
                if isinstance(body, Mapping):
                    entries.append((str(resource_type), str(name), body))
    return entries


def _tf_json_value(value: Any, path: str, facts: Any) -> Any:
    """One ``.tf.json`` attribute value in the plan-JSON encoding.

    A string carrying ``${`` becomes an
    :class:`gcp_grounding.facts.Unresolved` — the SUBSTRING rule
    :func:`gcp_grounding.facts.is_interpolated` states, so
    ``roles/${var.tier}.admin`` is refused too. A JSON OBJECT is a nested block
    and normalises to a one-element list of objects; an ARRAY of objects keeps
    its length. That is the shape ``tf_claims``' block helpers read, and it is
    what makes the two encodings produce the same triples.
    """
    if isinstance(value, str):
        if facts.is_interpolated(value):
            return facts.Unresolved("interpolation", path or "<root>",
                                    "a JSON string carrying '${'")
        return value
    if isinstance(value, Mapping):
        return [_tf_json_body(value, f"{path}[0].", facts)]
    if isinstance(value, list):
        return [_tf_json_body(item, f"{path}[{index}].", facts)
                if isinstance(item, Mapping)
                else _tf_json_value(item, f"{path}[{index}]", facts)
                for index, item in enumerate(value)]
    return value                        # numbers, booleans and null are literals


def _tf_json_body(body: Mapping[str, Any], prefix: str, facts: Any
                  ) -> dict[str, Any]:
    """One ``.tf.json`` body, comment keys dropped."""
    return {key: _tf_json_value(value, f"{prefix}{key}", facts)
            for key, value in body.items() if key != _COMMENT_KEY}


def _tf_json_triples(document: Any, facts: Any
                     ) -> tuple[tuple[str, str, Mapping[str, Any]], ...]:
    """``(address, resource_type, values)`` for one ``.tf.json`` document —
    the same contract :func:`gcp_grounding.tfsource.hcl.parse_config_file`
    hands the raw-``.tf`` arm, so both arms feed ONE pipeline."""
    return tuple((f"{resource_type}.{name}", resource_type,
                  _tf_json_body(body, "", facts))
                 for resource_type, name, body in _tf_json_entries(document))


# -- THE ONE TERRAFORM ENTRY POINT --------------------------------------------


@dataclass(frozen=True)
class TerraformProposal:
    """One terraform CONFIGURATION file read as a PROPOSAL.

    ``proposal`` is a :class:`gcp_grounding.engine.Proposal` over the SYNTHETIC
    PLAN :func:`gcp_grounding.tfsource.plan.as_plan_document` assembled, or
    ``None`` when the file could not be read at all or this checkout cannot
    grade terraform. ``note`` is the sentence that says which of those happened
    — always present when ``proposal`` is ``None``, and non-empty for a raw
    ``.tf`` that WAS read, because a static HCL read is a subset read and must
    say so.
    """

    proposal: Any = None
    note: str = ""


def terraform_route(path: str) -> bool | None:
    """``True`` for raw HCL, ``False`` for ``.tf.json``, ``None`` when *path* is
    not terraform CONFIGURATION.

    The one suffix decision, so :meth:`PolicyGroundingGate._check_one` and
    :func:`gcp_grounding.cli._ground` cannot disagree about which files are a
    terraform proposal. ``.tf.json`` is tested BEFORE ``.tf`` because it ends
    with both, and ``.tfstate`` is deliberately not terraform CONFIGURATION:
    state is never a proposal.
    """
    lower = path.lower()
    if not lower.endswith(_TERRAFORM_SUFFIXES):
        return None
    return not lower.endswith(".tf.json")


def read_tf_json(path: str, facts: Any) -> tuple[Any, tuple[str, ...], str]:
    """``.tf.json`` through ``json.load`` and NO parser at all.

    Loaded through the one fail-open loader :meth:`PolicyGroundingGate.
    _ground_with_state` already uses, so "not valid JSON" is phrased in exactly
    one place.
    """
    document, source, error = preflight._load_document(path)
    if error is not None:
        return None, (), f"{source}: {error} — nothing was checked"
    return _tf_json_triples(document, facts), (), ""


def read_hcl(path: str) -> tuple[Any, tuple[str, ...], str]:
    """Raw ``.tf`` through :mod:`gcp_grounding.tfsource.hcl`.

    The reader is resolved LAZILY — a checkout without the ``tfsource``
    subpackage must degrade rather than fail — and reports an unresolved path
    for the CONTAINING resource of every ``dynamic`` block and every
    ``count``/``for_each``. Nothing is stripped here: those paths are REPORTED,
    and the engine's downgrade rule turns every ``grounded`` on the document
    into ``unverified``.
    """
    hcl = _tf_module("hcl")
    if hcl is None:
        return None, (), _HCL_ABSENT_NOTE.format(path=path)
    if os.path.isdir(path):
        triples, unresolved = hcl.parse_config_dir(path)
    else:
        triples, unresolved = hcl.parse_config_file(path)
    return (triples,
            tuple(unresolved) + (_HCL_SUBSET_PATH.format(path=path),),
            _HCL_READ_NOTE.format(path=path))


def build_tf_proposal(engine: Any, facts: Any, plan: Any, path: str,
                      triples: Iterable[tuple[str, str, Mapping[str, Any]]],
                      unresolved: Iterable[str]) -> Any:
    """ASSEMBLE THEN PREPARE, and it is normative in that order.

    The synthetic plan document is built FIRST, from the raw block bodies, with
    :func:`gcp_grounding.tfsource.plan.as_plan_document`; then
    :func:`gcp_grounding.engine.prepare_proposal` is called EXACTLY ONCE on the
    assembled plan. One call yields one :class:`~gcp_grounding.engine.Proposal`
    whose ``unresolved`` tuple is single-sourced, so the ``proposal:unresolved``
    verdicts and the every-``grounded``-becomes-``unverified`` downgrade both
    key off the same tuple. Calling ``prepare_proposal`` per block body instead
    would produce N throwaway proposals whose ``unresolved`` tuples are free to
    be dropped while only the sanitized documents are kept — and dropping them
    loses the downgrade entirely, turning an interpolated firewall into a clean
    pass.

    The PER-BODY pass here is the sanitize half only, and it exists so every
    path can be RE-PREFIXED WITH ITS RESOURCE ADDRESS before the final proposal
    is constructed: the tuples are UNIONED, re-prefixed, and handed to the
    single ``prepare_proposal`` call as ``unknown_paths``, in exactly the
    spelling :meth:`gcp_grounding.tfsource.hcl.HclRead.unresolved_paths` uses,
    so the two arms name the same attribute the same way and the set collapses
    duplicates instead of double-reporting them.

    The proposal is handed to the engine as a TERRAFORM-PLAN-kind proposal, so
    ``tf_claims.terraform_plan_claims`` and every extractor registered through
    ``registry.tf_extractors`` apply unchanged. There is never a second
    extractor table.
    """
    objects = []
    paths = {str(entry) for entry in unresolved}
    for address, resource_type, values in triples:
        sanitized, stripped = facts.strip_unresolved(values)
        paths.update(f"{address}.{removed}" for removed in stripped)
        objects.append(facts.TfObject(
            address=address, type=resource_type,
            name=address.rsplit(".", 1)[-1],
            source=_HCL_PROPOSED, side="proposed", values=sanitized))
    document = plan.as_plan_document(objects)
    return engine.prepare_proposal(document, engine.TF_PLAN_KIND,
                                   source=path,
                                   unknown_paths=sorted(paths))


def terraform_proposal(path: str, *, raw: bool) -> TerraformProposal:
    """THE ONE ENTRY POINT for grading a ``.tf`` / ``.tf.json`` file.

    Every caller — :class:`PolicyGroundingGate` and
    :func:`gcp_grounding.cli._ground` alike — reaches
    ``plan.as_plan_document`` → ``engine.prepare_proposal`` through here and
    NEVER by preparing the raw ``{"resource": ...}`` body as a proposal of its
    own. That second route was retired because ``preflight.detect_kind`` does
    not recognize terraform's JSON configuration syntax: the raw body yielded
    kind ``None``, no claim was extracted, no per-resource counterpart was ever
    named, and a registered pair check therefore demanded a decision the CLI
    route never made.

    Never raises: an unreadable file, an unrecognized shape or a reader that is
    not part of this checkout all come back as ``proposal=None`` plus the note
    that says so.
    """
    engine = _optional("engine")
    facts = _optional("facts")
    plan = _tf_module("plan")
    missing = ("gcp_grounding.engine" if engine is None else
               "gcp_grounding.facts" if facts is None else
               "gcp_grounding.tfsource.plan" if plan is None else "")
    if missing:
        return TerraformProposal(
            note=_TF_ENGINE_ABSENT_NOTE.format(path=path, missing=missing))
    triples, unresolved, note = (read_hcl(path) if raw
                                 else read_tf_json(path, facts))
    if triples is None:
        return TerraformProposal(note=note)
    return TerraformProposal(
        proposal=build_tf_proposal(engine, facts, plan, path, triples,
                                   unresolved),
        note=note)


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
    #: This file's rows from :func:`gcp_grounding.explain_state.state_document`
    #: — which sources were read, which settings chose them, what each changed
    #: row was compared against and where they disagreed. Empty (the default,
    #: so existing construction sites are unaffected) when no state source was
    #: configured.
    state: tuple[Mapping[str, Any], ...] = ()

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
    #: Whether a current-state source was CONFIGURED — configured, not loaded
    #: successfully. It is what gates the ``state`` key of :meth:`to_dict`, so
    #: a run that configured nothing produces today's document exactly.
    state_configured: bool = False
    #: The rendered state-used-this-run block, or empty when no source was
    #: configured (a clean run stays byte-quiet).
    state_render: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """The hard gate: False iff some file failed (ungrounded or
        contradicted verdicts); ``unverified`` never fails it."""
        return all(f.status != "failed" for f in self.files)

    @property
    def state(self) -> tuple[Mapping[str, Any], ...]:
        """Every file's state rows, in file order — the aggregate matching
        :attr:`FileResult.state`."""
        return tuple(row for f in self.files for row in f.state)

    @property
    def risk(self) -> str:
        """One of :data:`RISK_LEVELS` — see the module docstring.

        A file that is otherwise ``ok`` but carries an
        :data:`ALWAYS_REPORT_KINDS` verdict — a drift, a baseline that could
        not be resolved, a source that contributed nothing — raises the run's
        risk to ``"low"``, NEVER to ``"high"``: the ok semantics are untouched
        and none of those verdicts is a finding about the change itself.
        """
        if any(f.status == "failed" for f in self.files):
            return "high"
        if any(f.policy_candidate and f.status == "unverified" for f in self.files):
            return "low"
        if any(v.status == "unverified" and v.kind in ALWAYS_REPORT_KINDS
               for f in self.files for v in f.verdicts):
            return "low"
        return "none"

    def counts(self) -> dict[str, int]:
        """File counts per status; every status key present even at zero."""
        return {s: sum(1 for f in self.files if f.status == s)
                for s in FILE_STATUSES}

    def findings(self) -> tuple[str, ...]:
        """Human-readable, path-prefixed findings for a generator's next
        prompt: every ungrounded/contradicted verdict (with did-you-mean
        suggestions inline), the unverified notes of policy-relevant files the
        gate could not judge at all — an unparseable ``*.policy.json`` is
        feedback too — and every :data:`ALWAYS_REPORT_KINDS` verdict whatever
        the file's status, deduplicated against that pass so a wholly
        unverified file never prints a line twice."""
        lines: list[str] = []
        for f in self.files:
            emitted: set[str] = set()
            for v in f.verdicts:
                if v.status in ("ungrounded", "contradicted"):
                    tip = (f" (did you mean: {', '.join(v.suggestions)}?)"
                           if v.suggestions else "")
                    lines.append(f"{f.path}: {v.status} {v.kind} — {v.message}{tip}")
            if f.policy_candidate and f.status == "unverified":
                for v in f.verdicts:
                    line = f"{f.path}: unverified — {v.message}"
                    emitted.add(line)
                    lines.append(line)
            for v in f.verdicts:
                if v.status != "unverified" or v.kind not in ALWAYS_REPORT_KINDS:
                    continue
                line = f"{f.path}: unverified — {v.message}"
                if line not in emitted:
                    emitted.add(line)
                    lines.append(line)
        return tuple(lines)

    def render(self) -> str:
        """The whole gate result as human-readable text: one header line,
        then each file's :class:`PolicyReport` render, indented, then — when a
        state source was configured — the state-used-this-run block."""
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
        lines.extend(self.state_render)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """The machine document for CI, versioned by :data:`GATE_SCHEMA`.

        The ``state`` keys — one aggregate and one per file — appear exactly
        when a state source was configured. That is what keeps the schema
        string honest without bumping it: a consumer that configures nothing
        receives today's document byte for byte, and a consumer that
        configures a source opted into the extra key by configuring one.
        """
        document = {
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
        if self.state_configured:
            for entry, f in zip(document["files"], self.files):
                entry["state"] = [dict(row) for row in f.state]
            document["state"] = [dict(row) for row in self.state]
        return document


@dataclass
class _StateView:
    """One resolved current-state view, cached by the directory it governs."""

    current: Any = None
    snapshot: Any = None
    ledger: Any = None
    settings: Any = None
    notes: tuple[Verdict, ...] = ()
    #: Whether this view's own notes have already been attached to a report.
    attached: bool = False
    #: The compiled rule set for these settings, built once per view.
    rules: Any = None


class PolicyGroundingGate:
    """The changed-file gate, configured once with the snapshot to ground
    against. Construction is strict (a broken snapshot is a setup error and
    raises); :meth:`check` is fail-open (bad *input* never raises).

    The first positional argument keeps its exact meaning: a
    :class:`GcpSnapshot` or a path to one. Because
    :class:`gcp_grounding.reconciled.ReconciledSnapshot` SUBCLASSES
    ``GcpSnapshot``, handing one straight in already works and needs no flag —
    ``resolve_sources`` is ignored for it and :attr:`source_notes` is empty,
    since the caller already resolved.

    The keyword arguments are the current-state input and are all off by
    default:

    ``current``
        the assembled current state — a ``sources.CurrentState``, a
        ``ReconciledSnapshot`` or a plain snapshot — used for every file.
    ``settings``
        a :class:`gcp_grounding.discovery.Settings` used for every file when
        per-file discovery is off: its ``targets`` map supplies the baseline
        target of a document that does not name its own resource, and its
        ``requirements`` names the compiled promises.
    ``options``
        a :class:`gcp_grounding.sources.SourceOptions` acting as the CLI layer
        of every settings resolution, and the base of a ``resolve_sources``
        construction.
    ``discover_config``
        resolve the settings PER EDITED FILE by walking up from that file, so
        an agent editing three modules gets three different, correct
        counterparts. Loads are cached by resolved config directory, so a
        ten-file diff in one repo does one load.
    ``resolve_sources``
        route construction through
        :func:`gcp_grounding.sources.load_current` instead of
        :meth:`GcpSnapshot.load`, so the primary snapshot is merged with every
        other configured source. Construction stays STRICT: a primary that
        will not load raises :class:`ValueError` exactly as today.
    """

    def __init__(self, snapshot: GcpSnapshot | str | os.PathLike[str], *,
                 current: Any = None, settings: Any = None, options: Any = None,
                 discover_config: bool = False,
                 resolve_sources: bool = False) -> None:
        self.settings = settings
        self.options = options
        self.discover_config = bool(discover_config)
        #: The notes :func:`gcp_grounding.sources.load_current` returned for the
        #: constructed view. ESTATE-WIDE, so they are attached ONCE per check
        #: call; see :meth:`_attach_notes`.
        self.source_notes: tuple[Verdict, ...] = ()
        self.current = current
        if isinstance(snapshot, GcpSnapshot):
            self.snapshot = snapshot
        elif resolve_sources:
            self.snapshot, resolved = self._resolve_primary(snapshot)
            if self.current is None:
                self.current = resolved
            self.source_notes = tuple(resolved.notes)
        else:
            self.snapshot = GcpSnapshot.load(snapshot)
        self.state_configured = bool(self.current is not None or self.discover_config)
        self._now: Any = None
        self._states: dict[str, _StateView] = {}
        self._notes_pending: list[Verdict] = []
        self._state_render: tuple[str, ...] = ()

    def _resolve_primary(self, path: Any) -> tuple[Any, Any]:
        """The primary snapshot through the one current-state assembler.

        STRICT, exactly as :meth:`GcpSnapshot.load` is: a source set that
        produces no snapshot at all is a setup error and raises, because a
        broken snapshot is not bad input.
        """
        sources = _optional("sources")
        if sources is None:
            raise ValueError("resolve_sources=True needs gcp_grounding.sources, "
                             "which is not part of this checkout")
        base = self.options
        if base is None and self.settings is not None:
            base = getattr(self.settings, "options", None)
        if base is None:
            base = sources.SourceOptions()
        state = sources.load_current(dataclasses.replace(base,
                                                         primary=os.fspath(path)))
        if state.snapshot is None:
            detail = (state.problem or "; ".join(v.message for v in state.notes)
                      or "no source produced a snapshot")
            raise ValueError(f"the current state could not be assembled from "
                             f"{os.fspath(path)}: {detail}")
        return state.snapshot, state

    # -- the run -------------------------------------------------------------

    def check(self, changed_files: Iterable[str | os.PathLike[str]], *,
              as_of: Any = _OMITTED) -> GateResult:
        """Ground every policy-relevant file in *changed_files* (duplicates
        are processed once, order preserved) and aggregate the outcome.
        Callers should pass paths that exist — a deleted file surfaces as an
        unreadable one, i.e. ``unverified``.

        *as_of* is THE clock boundary, resolved ONCE here through
        :func:`gcp_grounding.freshness.resolve_now` and threaded everywhere:
        into the source options every state load is built from, and into every
        ``EvalOptions``. **Omitting it RESOLVES it rather than dropping it.**
        The old reading — omitted means staleness is never evaluated — is a
        fail-open hole on exactly the path this input exists to protect, since
        the PostToolUse hook is invoked with one fixed command line and would
        otherwise treat a six-month-old auto-discovered ``terraform.tfstate``
        as current forever. ``resolve_now`` honours ``GCP_GROUNDING_NOW``, so a
        suite stays deterministic; passing ``as_of=None`` explicitly is the
        documented way to say the run pins no clock.
        """
        backend = get_solver().backend
        clock_notes: list[Verdict] = []
        self._now = self._resolve_clock(as_of, clock_notes)
        # The state cache and the attach-once flags are reset per call, so two
        # successive checks each attach their notes exactly once and a clock
        # threaded into this call never leaks into the next one.
        self._states = {}
        self._notes_pending = list(self.source_notes) + clock_notes
        self._state_render = ()
        results: list[FileResult] = []
        seen: set[str] = set()
        for raw in changed_files:
            path = os.fspath(raw)
            if path in seen:
                continue
            seen.add(path)
            results.append(self._check_one(path, backend))
        if self._notes_pending:
            logger.debug("gate: %d estate-wide source note(s) went unattached — no "
                         "policy-candidate file was grounded in this run",
                         len(self._notes_pending))
        result = GateResult(files=tuple(results),
                            captured_at=self.snapshot.captured_at,
                            backend=backend,
                            state_configured=self.state_configured,
                            state_render=self._state_render)
        logger.debug("gate: %d file(s) → ok=%s risk=%s %s",
                     len(results), result.ok, result.risk, result.counts())
        return result

    def _resolve_clock(self, as_of: Any, notes: list[Verdict]) -> Any:
        """The instant this run measures ages against, or ``None``.

        An unparseable pinned clock is a note rather than an exception: this is
        on ``check``'s never-raises path, and a run that says which clock it
        could not read is more useful than one that dies.
        """
        if as_of is None:
            return None
        freshness = _optional("freshness")
        if freshness is None:
            return None if as_of is _OMITTED else as_of
        try:
            return (freshness.resolve_now() if as_of is _OMITTED
                    else freshness.resolve_now(as_of))
        except ValueError as exc:
            notes.append(Verdict("unverified", "state:source", "<clock>", 0,
                                 f"the run's clock could not be resolved ({exc}) - "
                                 f"no age was checked against it"))
            return None

    # -- per-file ------------------------------------------------------------

    def _check_one(self, path: str, backend: str) -> FileResult:
        lower = path.lower()
        if lower.endswith(".tfstate"):
            return self._state_source_file(path, backend)
        raw = terraform_route(path)
        if raw is not None:
            return self._check_terraform(path, backend, raw=raw)
        if lower.endswith(".json"):
            if lower.endswith(_CANDIDATE_SUFFIXES):
                report, state = self._ground(path, backend)
                return self._file_result(path, report, candidate=True, state=state)
            sniffed = self._sniff(path)
            if sniffed == "state":
                return self._state_source_file(path, backend)
            if sniffed == "policy":
                report, state = self._ground(path, backend)
                return self._file_result(path, report, candidate=True, state=state)
            return self._unverified(
                path, backend, candidate=False,
                note=f"{path}: not recognized as an IAM policy, Org Policy or "
                     f"terraform plan document — not checked")
        # An extensionless file still reaches the state sniff: a `terraform
        # state pull > current` is a state file whatever it is called, and the
        # preflight plan-key set contains `terraform_version`, which EVERY
        # tfstate carries — so without this it classifies as a terraform plan
        # and degrades to a zero-claims unverified that reads like a clean run.
        if self._sniff(path) == "state":
            return self._state_source_file(path, backend)
        return self._unverified(
            path, backend, candidate=False,
            note=f"{path}: not a policy file "
                 f"(*.tf / *.tf.json / *.tfstate / *.json) — not checked")

    def _sniff(self, path: str) -> str:
        """What a file's CONTENT says it is: ``"state"``, ``"policy"`` or ``""``.

        THE V4-STATE SNIFF COMES FIRST, before the kind detector, so a state
        file with no ``.tfstate`` suffix routes into the state arm rather than
        into ``detect_kind`` — see :func:`_is_v4_state` for why it is one
        shared predicate and not a fourth ``version == 4``.

        Unreadable or invalid files sniff to ``""`` — by name alone they were
        never policy-relevant. RecursionError (deeply nested JSON) degrades the
        same way: check() never raises on its input.
        """
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError, RecursionError):
            return ""
        if _is_v4_state(doc):
            return "state"
        return "policy" if detect_kind(doc) is not None else ""

    def _sniffs_as_policy(self, path: str) -> bool:
        """Whether a plain ``.json`` file's content looks like a policy
        document. A v4 state file does NOT: it sniffs as ``"state"`` first, so
        the whole estate is never graded as if it had just been written."""
        return self._sniff(path) == "policy"

    # -- .tfstate: a source, never a proposal --------------------------------

    def _state_source_file(self, path: str, backend: str) -> FileResult:
        """Terraform state, refused as a proposal and pointed at the flag that
        makes it a BASELINE. Still a policy candidate, so the run's risk says
        a policy-relevant file went unjudged."""
        discover = _tf_module("discover")
        template = (discover.STATE_NOT_A_PROPOSAL if discover is not None
                    else _STATE_NOT_A_PROPOSAL_FALLBACK)
        note = template.format(path=path)
        if self._already_a_state_source(path):
            note += _ALREADY_A_STATE_SOURCE
        return self._unverified(path, backend, candidate=True, note=note)

    def _already_a_state_source(self, path: str) -> bool:
        """Whether this run's configured current state ALREADY reads *path*."""
        resolved = os.path.abspath(path)
        return any(os.path.abspath(entry) == resolved
                   for entry in self._configured_state_paths(path))

    def _configured_state_paths(self, path: str) -> list[str]:
        """Every state path this run was configured with — from the supplied
        ``current``, from the options and settings the gate holds, and from the
        state discovered beside *path* when per-file discovery is on."""
        holders: list[Any] = [self.current, self.options, self.settings]
        try:
            view = self._state_for(path)
        except Exception:                   # noqa: BLE001 — never raises here
            logger.debug("gate: the configured state could not be resolved for %s",
                         path, exc_info=True)
            view = None
        if view is not None:
            holders.extend([view.current, view.settings])
        found: list[str] = []
        for holder in holders:
            if holder is None:
                continue
            # `CurrentState.sources` is what actually loaded; a `SourceOptions`
            # (bare, or wrapped by a `Settings`) is what was asked for.
            for entry in getattr(holder, "sources", ()) or ():
                found.append(os.fspath(entry))
            options = holder if hasattr(holder, "terraform_state") else \
                getattr(holder, "options", None)
            for entry in getattr(options, "terraform_state", ()) or ():
                found.append(os.fspath(entry))
        return [entry for entry in found if entry]

    # -- .tf / .tf.json: the proposal IS the terraform ------------------------

    def _check_terraform(self, path: str, backend: str, *, raw: bool
                         ) -> FileResult:
        """One terraform CONFIGURATION file through the one HCL-to-claims path.

        Fail-open like every other arm: an unreadable file, an unrecognized
        shape or a reader that is not part of this checkout all land in an
        honest ``unverified``, never a crash.
        """
        try:
            report, state, candidate = self._terraform_report(path, backend,
                                                              raw=raw)
        except Exception as exc:            # noqa: BLE001 — the gate never raises
            logger.debug("fail-open: terraform routing crashed on %s", path,
                         exc_info=True)
            report = GroundingReport()
            report.backend = backend
            report.add(Verdict(
                "unverified", "document", path, 0,
                f"{path}: grounding crashed ({type(exc).__name__}: {exc}) "
                f"— nothing was checked"))
            state, candidate = (), True
        return self._file_result(path, report, candidate=candidate, state=state)

    def _terraform_report(self, path: str, backend: str, *, raw: bool
                          ) -> tuple[GroundingReport, tuple[Mapping[str, Any], ...],
                                     bool]:
        # THE ONE ENTRY POINT, shared with `cli._ground`: assemble the synthetic
        # plan, then prepare it exactly once. See `terraform_proposal`.
        built = terraform_proposal(path, raw=raw)
        if built.proposal is None:
            return self._note_only(path, backend, built.note)
        proposal, note = built.proposal, built.note
        engine = _optional("engine")
        view = self._state_for(path)
        if view is None:
            # No current state configured: today's plain grounding, reached
            # through the engine's OWN proposal stage so the `proposal:
            # unresolved` wording and the downgrade rule have exactly one
            # implementation rather than a second copy living here.
            report = GroundingReport()
            report.backend = backend
            engine._stage_proposal(report, proposal, self.snapshot)
            engine._downgrade_grounded(report, proposal)
            if self.state_configured:
                # Never silence, exactly as `_ground` does not: a configured
                # source no module in this checkout can read is a smaller
                # coverage than was asked for.
                report.add(Verdict(
                    "unverified", "state:source", path, 0,
                    f"a current-state source was configured, but the discovery "
                    f"modules are not part of this checkout - {path} was "
                    f"grounded against the vocabulary alone and NOTHING was "
                    f"compared against the estate"))
            state: tuple[Mapping[str, Any], ...] = ()
        else:
            report, state = self._ground_with_state(path, view, backend,
                                                    proposal=proposal)
        if note:
            report.add(Verdict("unverified", _UNRESOLVED_KIND, path, 0, note))
        return report, state, True

    def _note_only(self, path: str, backend: str, note: str
                   ) -> tuple[GroundingReport, tuple[Mapping[str, Any], ...], bool]:
        report = GroundingReport()
        report.backend = backend
        report.add(Verdict("unverified", "document", path, 0, note))
        return report, (), True

    def _ground(self, path: str, backend: str
                ) -> tuple[GroundingReport, tuple[Mapping[str, Any], ...]]:
        # ground_policy carries its own fail-open contract, and so does
        # engine.evaluate; the belt here is for anything that still escapes
        # (e.g. undecodable bytes), so the gate's own never-crash promise
        # doesn't ride on preflight's — or on the engine's.
        try:
            view = self._state_for(path)
            if view is None:
                report = ground_policy(path, self.snapshot)
                if self.state_configured:
                    # Never silence: a configured source that no module in this
                    # checkout can read is a smaller coverage than was asked for.
                    report.add(Verdict(
                        "unverified", "state:source", path, 0,
                        f"a current-state source was configured, but the discovery "
                        f"modules are not part of this checkout - {path} was "
                        f"grounded against the vocabulary alone and NOTHING was "
                        f"compared against the estate"))
                return report, ()
            return self._ground_with_state(path, view, backend)
        except Exception as exc:
            logger.debug("fail-open: grounding crashed on %s", path, exc_info=True)
            report = GroundingReport()
            report.backend = backend
            report.add(Verdict(
                "unverified", "document", path, 0,
                f"{path}: grounding crashed ({type(exc).__name__}: {exc}) "
                f"— nothing was checked"))
            return report, ()

    def _unverified(self, path: str, backend: str, candidate: bool,
                    note: str) -> FileResult:
        report = GroundingReport()
        report.backend = backend
        report.add(Verdict("unverified", "document", path, 0, note))
        return self._file_result(path, report, candidate)

    def _file_result(self, path: str, report: GroundingReport, candidate: bool,
                     state: tuple[Mapping[str, Any], ...] = ()) -> FileResult:
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
                          policy_candidate=candidate, report=policy_report,
                          state=state)

    # -- the current-state input ---------------------------------------------

    def _state_for(self, path: str) -> _StateView | None:
        """The current state governing *path*, or ``None`` when none is
        configured — in which case the caller does today's plain grounding.

        An explicitly supplied ``current`` wins over discovery: the caller
        already said which state this run compares against, and re-deriving one
        per file would silently replace it.
        """
        if not self.state_configured:
            return None
        if self.current is not None:
            view = self._states.get("")
            if view is None:
                snapshot, ledger = self._view_of(self.current)
                # A supplied current state's own notes are estate-wide too, and
                # go on exactly once — the constructor already carried them when
                # `resolve_sources` produced this state, so they are taken from
                # the view only when it did not.
                notes = (() if self.source_notes
                         else tuple(getattr(self.current, "notes", ()) or ()))
                view = _StateView(current=self.current, snapshot=snapshot,
                                  ledger=ledger, settings=self.settings,
                                  notes=notes)
                self._states[""] = view
            return view
        return self._discovered_state(path)

    def _discovered_state(self, path: str) -> _StateView | None:
        """The state discovered NEXT TO *path*, cached by config directory.

        THIS IS THE FIX for a hook command line being able to pin exactly one
        baseline for a whole session: the baseline is derived per file from the
        state discovered beside that file. Caching by the RESOLVED CONFIG
        DIRECTORY is what keeps a ten-file diff in one repo to one load, while
        a second file under a different config still gets its own.
        """
        discovery = _optional("discovery")
        sources = _optional("sources")
        if discovery is None or sources is None:
            return None
        config, problems = discovery.discover(path)
        auto = None
        if config is None:
            auto, detected = discovery.auto_detect(path)
            problems = tuple(problems) + tuple(detected)
        key = config.directory if config is not None else _start_directory(path)
        view = self._states.get(key)
        if view is not None:
            return view
        settings = discovery.resolve_settings(cli=self.options, config=config,
                                              auto=auto)
        state = sources.load_current(
            discovery.to_source_options(settings, as_of=self._now))
        notes = [Verdict("unverified", "state:source", key, 0, problem)
                 for problem in problems]
        if state.problem:
            notes.append(Verdict("unverified", "state:source", key, 0,
                                 f"{state.problem} - no current state was used for "
                                 f"the files under {key}"))
        notes.extend(state.notes)
        snapshot, ledger = self._view_of(state)
        view = _StateView(current=state, snapshot=snapshot, ledger=ledger,
                          settings=settings, notes=tuple(notes))
        self._states[key] = view
        return view

    @staticmethod
    def _view_of(current: Any) -> tuple[Any, Any]:
        """``(snapshot, ledger)`` through the ONE reader that knows the shapes,
        or ``(None, None)`` where it is not part of this checkout."""
        baseline = _optional("baseline")
        if baseline is None:
            return None, None
        try:
            return baseline.current_view(current)
        except TypeError:
            logger.debug("the configured current state has no readable snapshot",
                         exc_info=True)
            return None, None

    # -- the three-input evaluation ------------------------------------------

    def _ground_with_state(self, path: str, view: _StateView, backend: str,
                           proposal: Any = None
                           ) -> tuple[GroundingReport, tuple[Mapping[str, Any], ...]]:
        """One file through the three-input engine: proposal, current, rules.

        *proposal* is supplied ALREADY BUILT by the terraform arms, which
        assemble a synthetic plan out of block bodies rather than grading the
        file's own JSON; everything else about the run — the baseline, the
        rules, the drift pass and the redaction boundary — is identical, so
        terraform reaches the pair tier by the same road every other proposal
        does.
        """
        engine = _optional("engine")
        if engine is None:
            report = ground_policy(path, self.snapshot)
            report.add(Verdict(
                "unverified", "state:source", path, 0,
                f"a current-state source was configured, but gcp_grounding.engine "
                f"is not part of this checkout - {path} was grounded against the "
                f"vocabulary alone and NOTHING was compared against the estate"))
            self._attach_notes(report, view)
            return report, ()

        if proposal is None:
            # The same fail-open document loading `ground_policy` does, reached
            # through the one loader rather than re-spelled: two copies of the
            # "not valid JSON" phrasing is two messages that can drift apart.
            document, source, error = preflight._load_document(path)
            if error is not None:
                report = GroundingReport()
                report.backend = backend
                report.add(Verdict("unverified", "document", source, 0,
                                   f"{source}: {error} — nothing was checked"))
                self._attach_notes(report, view)
                return report, ()
            kind = detect_kind(document)
            proposal = engine.prepare_proposal(document, kind, source=source)
        settings = {"as_of": self._now.isoformat() if self._now is not None else None,
                    "drift": self._drift_mode(engine, view)}
        hints = self._hints(path, view)
        if hints is not None:
            settings["hints"] = hints
        options = engine.EvalOptions(**settings)
        if view.rules is None:
            # Compiled ONCE per view: the settings that name the requirements
            # are per config directory, so re-compiling them per file would
            # re-read and re-admit the same promises for every changed file.
            view.rules = self._rule_set(engine, view)
        result = engine.evaluate(proposal, view.current, view.rules,
                                 options=options)
        report = result.report

        # The notes go on BEFORE the scrub, so a note that quotes a value the
        # loading boundary withheld is scrubbed with everything else.
        self._attach_notes(report, view)
        drift = _optional("drift")
        if drift is not None:
            drift.postpass(report, view.snapshot)
        redact = _optional("redact")
        sources = _optional("sources")
        if redact is not None and sources is not None:
            redact.scrub_report(sources.vault(), report)

        return report, self._state_rows(result, view)

    def _rule_set(self, engine: Any, view: _StateView) -> Any:
        """THE THIRD INPUT: the built-in checks plus the compiled promises the
        per-file settings name.

        ``engine.evaluate`` takes a :class:`~gcp_grounding.engine.RuleSet` and
        nobody else on the gate path builds one, so without this the promise
        input reaches the agentic path NOT AT ALL —
        ``preflight.ground_policy``'s own ``rules=`` parameter is bypassed the
        moment this helper routes through the engine, and this is the only
        place it can come back.

        Fails OPEN with exactly one note when the compiler is unavailable or a
        requirements document will not load: never a raise, and never silence.
        """
        requirements = getattr(view.settings, "requirements", "") or ""
        if not requirements:
            return engine.RuleSet()
        sec_rules = _optional("sec_rules")
        if sec_rules is None:
            return engine.RuleSet(carry_verdicts=(Verdict(
                "unverified", engine.RULES_KIND, requirements, 0,
                f"the requirements at '{requirements}' were configured, but "
                f"gcp_grounding.sec_rules is not part of this checkout - no "
                f"compiled promise was evaluated"),))
        try:
            # A LIST, never the bare string: `load_rules` iterates its argument,
            # so a path handed over directly would be iterated into characters.
            if os.path.isdir(requirements):
                compiled, verdicts = sec_rules.load_directory(requirements)
            else:
                compiled, verdicts = sec_rules.load_rules([requirements])
        except Exception as exc:            # noqa: BLE001 - fail OPEN, one note
            logger.debug("fail-open: loading requirements %s raised", requirements,
                         exc_info=True)
            return engine.RuleSet(carry_verdicts=(Verdict(
                "unverified", engine.RULES_KIND, requirements, 0,
                f"the requirements at '{requirements}' could not be compiled "
                f"({type(exc).__name__}: {exc}) - no promise was evaluated"),))
        return engine.RuleSet(compiled=tuple(compiled),
                              carry_verdicts=tuple(verdicts))

    @staticmethod
    def _drift_mode(engine: Any, view: _StateView) -> str:
        """The configured drift policy in the engine's own two-value
        vocabulary: only ``block`` blocks, everything else reports."""
        options = getattr(view.settings, "options", None)
        policy = getattr(options, "drift_policy", "") or ""
        return "block" if policy == "block" else engine.DEFAULT_DRIFT_MODE

    def _hints(self, path: str, view: _StateView) -> Any:
        """The per-file baseline hints: the configured target for THIS file.

        A document that does not name its own resource — an IAM allow or deny
        policy — gets its target from the settings ``targets`` map keyed by the
        edited path, and from nothing else. A target is never guessed from a
        file name.
        """
        baseline = _optional("baseline")
        if baseline is None:
            return None
        targets = getattr(view.settings, "targets", None) or {}
        ref = targets.get(os.path.abspath(path)) or targets.get(path)
        if ref is None:
            return baseline.Hints(source=path)
        return baseline.Hints(source=path,
                              category=getattr(ref, "category", ""),
                              targets={path: getattr(ref, "key", "")})

    def _state_rows(self, result: Any, view: _StateView
                    ) -> tuple[Mapping[str, Any], ...]:
        """This file's rows of the state document, and — once per run — the
        human block :meth:`GateResult.render` appends."""
        explain_state = _optional("explain_state")
        if explain_state is None:
            return ()
        document = explain_state.state_document(result, view.ledger, view.settings)
        if not self._state_render:
            self._state_render = tuple(
                explain_state.state_lines(result, view.ledger, view.settings))
        return tuple({"row": block, **row} for block in _STATE_BLOCKS
                     for row in document.get(block, ()))

    def _attach_notes(self, report: GroundingReport, view: _StateView) -> None:
        """NOTE PLACEMENT, and why it is once.

        Source notes are ESTATE-WIDE and not file-specific, so attaching a copy
        to every file's report would multiply them by the changed-file count
        and inflate every count that reads them. They go ONCE, onto the FIRST
        policy-candidate file the gate actually grounds, in input order —
        deterministic because the changed-file order is the caller's and the
        flags are reset at the top of :meth:`check`, so two successive check
        calls each attach exactly once. When no file is grounded nothing is
        attached and the fact is logged at debug.
        """
        if self._notes_pending:
            for note in self._notes_pending:
                report.add(note)
            self._notes_pending = []
        if view.notes and not view.attached:
            for note in view.notes:
                report.add(note)
            view.attached = True


def _start_directory(path: str) -> str:
    """The directory the walk for *path* starts in — the cache key when no
    config file governs it."""
    resolved = os.path.abspath(path)
    return resolved if os.path.isdir(resolved) else os.path.dirname(resolved)
