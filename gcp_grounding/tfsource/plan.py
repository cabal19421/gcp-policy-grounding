"""THE plan-JSON reader: ``prior_state`` and ``change.before`` as CURRENT,
``resource_changes`` and ``planned_values`` as PROPOSED.

Layer 1 of the pipeline described in :mod:`gcp_grounding.tfsource`, and the ONE
place a ``terraform show -json`` plan is decoded. All FOUR input shapes a plan
document can carry are handled here, in one module, because they are four views
of one file and a second decoder is a second place for the CURRENT/PROPOSED
split to be wrong:

- **ARM 1** — ``prior_state.values.root_module`` as CURRENT at source
  ``tfplan-prior``, recursing ``child_modules``. It is the highest-fidelity
  terraform current-state view there is, because terraform refreshed it against
  the live API moments before writing the plan. When ``prior_state`` is absent
  this arm emits NOTHING, adds :data:`NO_PRIOR_STATE_NOTE`, and **never** falls
  back to ``planned_values``, which is the PROPOSED side.
- **ARM 2** — ``change.before`` as CURRENT for addresses ``prior_state`` does
  not cover. An entry whose ``before`` is null is skipped: a pure create
  legitimately has no predecessor. A before-side fact takes PRECEDENCE over a
  prior-state fact for the same key, because a change's ``before`` mapping is
  the exact predecessor of the exact resource under review.
- **ARM 3** — the PROPOSED side, at source ``tfplan-planned`` and side
  ``proposed``. ``resource_changes`` FIRST, because it is the only place
  ``actions`` live, then ``planned_values`` for the addresses
  ``resource_changes`` did not cover, at a no-op action.
- **ARM 4** — the bare ``values.root_module`` state representation that
  ``terraform show -json`` emits for a STATE file. It is state, so it is read at
  source ``tfstate``. :attr:`PlanRead.arms` records which arms ran.

WHY ARM 1 AND ARM 3 MAY NEVER SHARE A SOURCE SPELLING
-----------------------------------------------------
**This paragraph is normative.** ARM 3 stamps :data:`PROPOSED_SOURCE`
(``tfplan-planned``) and side ``proposed``; ARM 1 stamps :data:`PRIOR_SOURCE`
(``tfplan-prior``) and side ``current``. Stamping both arms with one source
would make :class:`gcp_grounding.facts.TfObject`'s biconditional — a proposed
source if and only if the proposed side — either unsatisfiable or vacuous, and
it would leave the merge's step-1 partition resting on a ``side`` field that
nothing structurally constrains. That biconditional IS the laundering guard: it
is what makes it impossible to read a proposed change back as evidence of what
currently exists, and so to ground a change against itself. The two spellings
are taken from :mod:`gcp_grounding.tfsource.discover`'s translation maps rather
than written out here, and :func:`_check_sources` re-checks the disjointness at
import time.

THE DELETE RULE
---------------
When ``after`` is null, ``before`` is set and the action is ``delete``, the
proposed object is built from ``change.before``. A deletion then becomes A FACT
ABOUT WHAT IS BEING REMOVED, so a check can say "this proposal removes the deny
that blocks port 22" instead of seeing nothing at all. Without it a destroy plan
is indistinguishable from an empty plan, which is the single most dangerous
change a gate can wave through.

AFTER-UNKNOWN
-------------
An attribute whose value is not yet known is OMITTED from ``after`` ENTIRELY,
and terraform records it by putting ``true`` at that position in the parallel
``after_unknown`` mirror. A missing key is therefore ambiguous between
*genuinely unset* and *not yet known* — and the ambiguity bites hardest on
exactly the resources a plan is least certain about, the ones being created,
where almost every computed attribute is unknown. Reading such a key as unset
turns "we cannot tell" into "it is empty", which is a clean pass over an
attribute nobody has seen. So :func:`unknown_marked` walks the mirror and
CREATES the key at every position where the mirror is exactly ``True``, holding
an ``Unresolved("unknown_after_apply", path)`` — a value that refuses
truthiness, so no check can turn it into a decision. The same walk runs for
``before_unknown``. Lists are mirrored element-wise.

:func:`after_unknown_paths`, :func:`unknown_marked` and :func:`sensitive_paths`
are exported for the proposal side so no call site has to remember the
derivation.

REDACTION runs BEFORE the :class:`~gcp_grounding.facts.TfObject` is built,
through the one boundary in :mod:`gcp_grounding.redact`, driven by the
``after_sensitive`` / ``before_sensitive`` mirrors (or, for a
values-representation, ``sensitive_values``) plus the name heuristic. It runs
BEFORE the unknown marking so a plaintext still reaches the vault. No logger
call in this module formats an attribute value except through
:func:`gcp_grounding.facts.safe_repr`, and ``outputs`` are read only far enough
to note that a sensitive one exists.

``resource_drift`` IS COLLECTED AS ADDRESSES ONLY
-------------------------------------------------
Never as a second object set: ``prior_state`` already reflects the refresh that
detected the drift, so a second set of the same objects would double-count every
one of them. But the addresses MUST still reach the operator — a note on the
reader is invisible to the agent, and terraform's own detected drift is exactly
the signal a human wants to see. :func:`source_record` carries them onto the
ledger as a ``resource_drift`` note keyed to the plan artifact, and the drift
surface renders ONE AGGREGATE verdict of the EXISTING ``drift`` kind naming the
count and the first five addresses — the existing spelling, already in the
gate's always-report set, so no vocabulary grows.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Mapping, Sequence

from ..core.log import get_logger
from ..facts import (MAX_DEPTH, PROPOSED_SOURCES, TfObject, Unresolved,
                     safe_repr, unresolved_in)
from ..provenance import SourceRecord
from ..redact import SecretVault, redact
from .discover import (MAX_ARTIFACT_BYTES, PROPOSED_SOURCE_FOR_KIND,
                       SOURCE_FOR_KIND)

logger = get_logger(__name__)

__all__ = [
    "PRIOR_SOURCE",
    "PROPOSED_SOURCE",
    "STATE_SOURCE",
    "FORMAT_MAJOR",
    "UNKNOWN_REASON",
    "ACTIONS",
    "FALLBACK_ACTION",
    "ARM_PRIOR_STATE",
    "ARM_CHANGE_BEFORE",
    "ARM_PROPOSED",
    "ARM_STATE_VALUES",
    "ARMS",
    "NO_PRIOR_STATE_NOTE",
    "NEVER_COMPLETE_NOTE",
    "NOTHING_READ_NOTE",
    "FORMAT_VERSION_REFUSED",
    "NOT_A_PLAN",
    "DRIFT_NOTE",
    "normalize_action",
    "after_unknown_paths",
    "before_unknown_paths",
    "unknown_marked",
    "sensitive_paths",
    "mirror_paths",
    "PlanRead",
    "read_plan",
    "read_plan_document",
    "drift_note",
    "source_record",
    "as_plan_document",
]

#: The CURRENT-state spelling ARM 1 and ARM 2 stamp. Taken from the discoverer's
#: translation map rather than written out, because that map is the ONE
#: kind-to-source translation in this package.
PRIOR_SOURCE = SOURCE_FOR_KIND["plan_json"]

#: The PROPOSED spelling ARM 3 stamps. See the module docstring: this may never
#: be :data:`PRIOR_SOURCE`.
PROPOSED_SOURCE = PROPOSED_SOURCE_FOR_KIND["plan_json"]

#: The spelling ARM 4 stamps. A ``terraform show -json`` state representation IS
#: state, re-encoded, so it collapses onto ``tfstate`` exactly as
#: ``discover.SOURCE_FOR_KIND`` says it does.
STATE_SOURCE = SOURCE_FOR_KIND["state_json"]

#: The only plan-format MAJOR version this reader decodes. The MINOR is
#: deliberately NOT pinned: terraform bumps it for additive changes, and
#: refusing next month's plan for an added key is a gate that stops working for
#: no reason.
FORMAT_MAJOR = 1

#: The ``facts.UNRESOLVED_REASONS`` member every ``after_unknown`` marker
#: carries.
UNKNOWN_REASON = "unknown_after_apply"


def _check_sources() -> None:
    """THE LAUNDERING GUARD, re-checked at import.

    By ``raise`` rather than ``assert`` so ``python -O`` cannot strip the one
    check standing between a typo and a PROPOSED change stamped as evidence of
    what currently exists.
    """
    if PROPOSED_SOURCE not in PROPOSED_SOURCES:
        raise ValueError(f"PROPOSED_SOURCE {PROPOSED_SOURCE!r} is not one of "
                         f"facts.PROPOSED_SOURCES {list(PROPOSED_SOURCES)}")
    for name, value in (("PRIOR_SOURCE", PRIOR_SOURCE),
                        ("STATE_SOURCE", STATE_SOURCE)):
        if value in PROPOSED_SOURCES:
            raise ValueError(f"{name} {value!r} is a PROPOSED spelling; ARM 1, ARM 2 "
                             f"and ARM 4 read CURRENT state and may never carry one")
    if PRIOR_SOURCE == PROPOSED_SOURCE:
        raise ValueError("the prior-state and planned spellings are identical; the "
                         "TfObject biconditional that keeps a proposal out of the "
                         "current-state view would be vacuous")


_check_sources()


# -- the action vocabulary ----------------------------------------------------

#: Every action name this reader emits. ``replace`` is this reader's own
#: spelling of the two-element ``["delete", "create"]`` pair terraform writes;
#: there is no fifth status, no new verdict status and no new kind here.
ACTIONS = ("no-op", "create", "read", "update", "delete", "replace")

#: What an unrecognised action list becomes. ``update`` is the conservative
#: answer: it says the object changes without claiming to know how, where
#: ``no-op`` would claim nothing happens and ``create``/``delete`` would invent
#: an existence change.
FALLBACK_ACTION = "update"

_ACTION_MAP: dict[tuple[str, ...], str] = {
    ("no-op",): "no-op",
    ("create",): "create",
    ("read",): "read",
    ("update",): "update",
    ("delete",): "delete",
    # THE TWO-ELEMENT REPLACEMENT, in both orders terraform writes it:
    # delete-then-create is the default, create-then-delete is what
    # `create_before_destroy` produces.
    ("delete", "create"): "replace",
    ("create", "delete"): "replace",
}


def normalize_action(actions: Any) -> tuple[str, str]:
    """One ``change.actions`` array → ``(action, note)``.

    ``note`` is empty for a recognised list and names the fallback otherwise.
    Anything this reader does not recognise becomes :data:`FALLBACK_ACTION` WITH
    a note rather than being dropped: an entry with no action still describes a
    resource, and silently discarding it is how a change disappears from a plan.
    """
    if isinstance(actions, str) or not isinstance(actions, Sequence):
        return FALLBACK_ACTION, (
            f"'actions' is {safe_repr(actions)} and not an array; the change was "
            f"read as {FALLBACK_ACTION!r}")
    key = tuple(str(item) for item in actions)
    found = _ACTION_MAP.get(key)
    if found is not None:
        return found, ""
    return FALLBACK_ACTION, (
        f"action {list(key)} is not one of {[list(k) for k in _ACTION_MAP]}; it "
        f"was read as {FALLBACK_ACTION!r} rather than dropped")


# -- the notes ----------------------------------------------------------------

ARM_PRIOR_STATE = "prior_state.values.root_module"
ARM_CHANGE_BEFORE = "resource_changes[].change.before"
ARM_PROPOSED = "resource_changes[]+planned_values"
ARM_STATE_VALUES = "values.root_module"

#: The four input shapes, in the order the reader tries them.
ARMS = (ARM_PRIOR_STATE, ARM_CHANGE_BEFORE, ARM_PROPOSED, ARM_STATE_VALUES)

#: THE NOTE that says a plan carried no refreshed read of reality — and says,
#: in as many words, what this reader refused to do about it.
NO_PRIOR_STATE_NOTE = (
    "{path}: this plan carries no 'prior_state', so it holds NO refreshed read "
    "of what currently exists. Nothing was taken from 'planned_values' to stand "
    "in for it: planned values are the PROPOSED side, and reading them as "
    "current state would ground the change against itself and pass every "
    "widening check it should have caught. Only 'change.before' contributed "
    "current facts here."
)

#: Carried by every successful read. ``provenance.CategoryScope`` caps a
#: ``tfplan-prior`` scope at ``partial`` structurally; this note is what makes
#: the reason readable in the ledger.
NEVER_COMPLETE_NOTE = (
    "{path}: a terraform plan refreshed only the resources it was going to "
    "touch, so its prior state covers those and NOTHING else. Resources created "
    "by hand, by another pipeline, by another workspace or by another state file "
    "are invisible to it, and no category may be resolved absent from it."
)

NOTHING_READ_NOTE = (
    "{path}: {entries} entr(y|ies) were read and ZERO objects survived. That is "
    "coverage of NOTHING, not an empty estate; the notes above name every entry "
    "that was skipped and why."
)

FORMAT_VERSION_REFUSED = (
    "{path}: this is terraform JSON in format version {version!r}. Only major "
    "version {expected} is understood here, and an unknown major is REFUSED "
    "rather than read against a schema it may not follow — a misread plan is a "
    "confident answer about the wrong document. The MINOR is not pinned."
)

NOT_A_PLAN = (
    "{path}: this document carries none of 'prior_state', 'resource_changes', "
    "'planned_values' or 'values.root_module', so there is no terraform plan or "
    "state representation in it to read. NOTHING was captured."
)

#: THE DRIFT NOTE. Keyed to the plan artifact and carried onto the ledger by
#: :func:`source_record`, because a note that stops at the reader is a note the
#: operator never sees.
DRIFT_NOTE = (
    "resource_drift: terraform detected drift on {count} resource(s) "
    "({sample}). The addresses are recorded and NO objects were taken from "
    "'resource_drift': 'prior_state' already reflects that refresh, so a second "
    "object set would double-count every one of them."
)

_ERRORED_NOTE = (
    "{path}: the plan is marked 'errored': true, so terraform did not finish "
    "planning. What it did write was read, and every object from it is as "
    "partial as the run that produced it."
)

_ROOT_PATH = "<root>"


# -- the mirror walkers -------------------------------------------------------


def _is_sequence(value: Any) -> bool:
    """A JSON-ish array — a string is a scalar here, never a sequence."""
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _child(path: str, key: Any) -> str:
    return f"{path}.{key}" if path else str(key)


def _walk_true(mirror: Any, path: str, depth: int) -> Iterator[str]:
    # EXACTLY ``True``, by identity: terraform writes ``false`` for a known
    # value and ``{}``/``[]`` for a container with nothing marked under it, and
    # a truthiness test would read a non-empty container as a mark.
    if mirror is True:
        yield path or _ROOT_PATH
        return
    if depth >= MAX_DEPTH:
        return
    if isinstance(mirror, Mapping):
        # Sorted, so the order depends on the document's CONTENT and not on how
        # the parser happened to build its dicts — the same discipline
        # ``facts.unresolved_in`` follows, so the two agree path for path.
        for key, sub in sorted(mirror.items(), key=lambda kv: str(kv[0])):
            yield from _walk_true(sub, _child(path, key), depth + 1)
    elif _is_sequence(mirror):
        for index, sub in enumerate(mirror):
            yield from _walk_true(sub, f"{path}[{index}]", depth + 1)


def mirror_paths(mirror: Any) -> tuple[str, ...]:
    """Every attribute path a plan mirror marks with exactly ``True``.

    THE ONE walker over the four parallel mirrors a plan carries —
    ``after_unknown``, ``before_unknown``, ``after_sensitive``,
    ``before_sensitive`` — and over a values-representation's
    ``sensitive_values``. They share a shape, so they share a walker; four
    hand-written walks would be four chances to disagree about what a mark on a
    container means.
    """
    return tuple(_walk_true(mirror, "", 0))


def _has_true(mirror: Any, depth: int = 0) -> bool:
    if mirror is True:
        return True
    if depth >= MAX_DEPTH:
        return False
    if isinstance(mirror, Mapping):
        return any(_has_true(sub, depth + 1) for sub in mirror.values())
    if _is_sequence(mirror):
        return any(_has_true(sub, depth + 1) for sub in mirror)
    return False


def _mark(value: Any, mirror: Any, path: str, depth: int) -> Any:
    if mirror is True:
        return Unresolved(UNKNOWN_REASON, path or _ROOT_PATH)
    if not _has_true(mirror):
        # Nothing under here is unknown, so nothing is created. This is what
        # keeps a ``false`` and an empty container from minting a key.
        return value
    if depth >= MAX_DEPTH:
        # FAIL SAFE at the cap: something below IS unknown and this reader will
        # not descend to it, so the subtree is refused whole rather than handed
        # over as if every key in it were known.
        return Unresolved("depth_cap", path or _ROOT_PATH,
                          f"unknown-after-apply mirror nests past MAX_DEPTH={MAX_DEPTH}")
    if isinstance(mirror, Mapping):
        out = dict(value) if isinstance(value, Mapping) else {}
        for key, sub in mirror.items():
            if _has_true(sub):
                # CREATE the key: an unknown attribute is absent from `after`
                # entirely, and a missing key is what this whole walk exists to
                # disambiguate.
                out[key] = _mark(out.get(key), sub, _child(path, key), depth + 1)
        return out
    if _is_sequence(mirror):
        out_list = list(value) if _is_sequence(value) else []
        for index, sub in enumerate(mirror):
            if not _has_true(sub):
                continue
            while len(out_list) <= index:
                out_list.append(None)
            out_list[index] = _mark(out_list[index], sub, f"{path}[{index}]",
                                    depth + 1)
        return out_list
    return value


def _change_of(change: Any) -> Mapping[str, Any]:
    """A ``resource_changes`` entry OR the ``change`` object itself → the change
    object. Both spellings are accepted because a caller holding the entry and a
    caller holding the change are equally natural, and guessing wrong silently
    yields an empty answer."""
    if not isinstance(change, Mapping):
        return {}
    inner = change.get("change")
    if isinstance(inner, Mapping):
        return inner
    return change


def after_unknown_paths(change: Any) -> tuple[str, ...]:
    """Every attribute path this change's ``after_unknown`` marks unknown.

    Exported for the proposal side: ``engine.prepare_proposal`` emits one
    verdict per path, so an attribute nobody has seen cannot buy a clean pass.
    """
    return mirror_paths(_change_of(change).get("after_unknown"))


def before_unknown_paths(change: Any) -> tuple[str, ...]:
    """The same walk over ``before_unknown`` — the predecessor's unknowns."""
    return mirror_paths(_change_of(change).get("before_unknown"))


def unknown_marked(change: Any, *, side: str = "after") -> Any:
    """This change's values with an ``Unresolved(UNKNOWN_REASON, path)`` CREATED
    at every position its unknown mirror marks.

    ``side`` selects ``after``/``after_unknown`` (the default, the proposal) or
    ``before``/``before_unknown``. The values are returned as the plan wrote
    them otherwise; redaction is a separate boundary and is applied by the
    reader, not here.
    """
    if side not in ("after", "before"):
        raise ValueError(f"unknown_marked side must be 'after' or 'before', got {side!r}")
    body = _change_of(change)
    return _mark(body.get(side), body.get(f"{side}_unknown"), "", 0)


def sensitive_paths(change: Any, *, side: str = "after") -> tuple[str, ...]:
    """Every attribute path this change's sensitivity mirror marks.

    ``side`` selects ``after_sensitive`` (the default, the proposal) or
    ``before_sensitive``. Diagnostic only — it names attributes and never
    values, so it is safe in a note, a log line and a verdict.
    """
    if side not in ("after", "before"):
        raise ValueError(f"sensitive_paths side must be 'after' or 'before', got {side!r}")
    return mirror_paths(_change_of(change).get(f"{side}_sensitive"))


# -- the result ---------------------------------------------------------------


@dataclass(frozen=True)
class PlanRead:
    """One plan document, read.

    ``current`` holds ARM 1, ARM 2 and ARM 4 objects (side ``current``);
    ``proposed`` holds ARM 3's (side ``proposed``). They are separate tuples
    rather than one list with a filter, because every consumer wants exactly one
    of them and a filter is a place to forget the predicate.

    ``drift_addresses`` are terraform's OWN detected-drift addresses, carried as
    addresses and never as objects — see the module docstring.

    ``ok is False`` always comes with at least one note saying why, and never
    with objects: an empty success is a clean bill of health for a plan nobody
    read.
    """

    ok: bool = False
    current: tuple[TfObject, ...] = ()
    proposed: tuple[TfObject, ...] = ()
    notes: tuple[str, ...] = ()
    drift_addresses: tuple[str, ...] = ()
    actions: Mapping[str, str] = field(default_factory=dict)
    arms: tuple[str, ...] = ()
    format_version: str = ""
    terraform_version: str = ""
    errored: bool = False
    captured_at: str = ""
    path: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "current", tuple(self.current))
        object.__setattr__(self, "proposed", tuple(self.proposed))
        object.__setattr__(self, "notes", tuple(self.notes))
        object.__setattr__(self, "drift_addresses", tuple(self.drift_addresses))
        object.__setattr__(self, "arms", tuple(self.arms))
        object.__setattr__(self, "actions", dict(self.actions))
        if not self.ok and (self.current or self.proposed):
            raise ValueError("a refused PlanRead carries no objects; a partial read "
                             "of a plan is a partial estate nobody declared")
        if not self.ok and not self.notes:
            raise ValueError("a refused PlanRead must say why; a silent refusal is "
                             "indistinguishable from an empty plan")

    @property
    def objects(self) -> tuple[TfObject, ...]:
        """Both sides, current first — for a caller that genuinely wants all of
        them (the census, the artifact fingerprint) and is not deciding
        anything from the side."""
        return self.current + self.proposed

    def current_by_address(self) -> dict[str, TfObject]:
        """Address → current object. ARM 2 already resolved the overlap, so the
        last writer here is the only writer."""
        return {obj.address: obj for obj in self.current}

    def proposed_by_address(self) -> dict[str, TfObject]:
        return {obj.address: obj for obj in self.proposed}

    def action_of(self, address: str) -> str:
        """The normalised action proposed for *address*, or ``""``."""
        return self.actions.get(address, "")


# -- the reader ---------------------------------------------------------------


def _mtime_utc(mtime: float) -> str:
    """A POSIX mtime in the snapshot's ``...Z`` form, mirroring
    ``fetch.fresh_captured_at`` so two captures stamp comparably."""
    return datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_plan(path: str | os.PathLike[str], *, captured_at: str | None = None,
              vault: SecretVault | None = None,
              max_bytes: int = MAX_ARTIFACT_BYTES) -> PlanRead:
    """Read one ``terraform show -json`` document from disk. NEVER RAISES.

    An unreadable file, an oversize one, undecodable bytes and unparseable JSON
    each come back as ``ok=False`` with a note — a reader that throws inside a
    capture is a capture that decided nothing.

    ``captured_at`` defaults to the plan's OWN ``timestamp`` when it carries
    one, which is the moment terraform refreshed, and only then to the file's
    mtime. A caller may pin it.
    """
    fspath = os.fspath(path)
    try:
        stat = os.stat(fspath)
        if stat.st_size > max_bytes:
            return PlanRead(
                ok=False, path=fspath, captured_at=captured_at or "",
                notes=(f"{fspath}: the file is {stat.st_size} bytes, over the "
                       f"{max_bytes}-byte artifact limit, and was not opened; "
                       f"NOTHING was captured from it.",))
        with open(fspath, "rb") as handle:
            payload = handle.read(max_bytes + 1)
    except OSError as exc:
        return PlanRead(
            ok=False, path=fspath, captured_at=captured_at or "",
            notes=(f"{fspath}: the plan file could not be read ({exc}) — NOTHING "
                   f"was captured from it.",))
    if len(payload) > max_bytes:
        return PlanRead(
            ok=False, path=fspath, captured_at=captured_at or "",
            notes=(f"{fspath}: the file grew past the {max_bytes}-byte artifact "
                   f"limit while it was being read; NOTHING was captured.",))

    try:
        document = json.loads(payload.decode("utf-8"))
    except UnicodeDecodeError as exc:
        return PlanRead(
            ok=False, path=fspath, captured_at=captured_at or "",
            notes=(f"{fspath}: the plan file is not UTF-8 text ({exc}); NOTHING "
                   f"was captured.",))
    except json.JSONDecodeError as exc:
        return PlanRead(
            ok=False, path=fspath, captured_at=captured_at or "",
            notes=(f"{fspath}: the plan file is not valid JSON ({exc}); NOTHING "
                   f"was captured.",))
    except RecursionError:
        return PlanRead(
            ok=False, path=fspath, captured_at=captured_at or "",
            notes=(f"{fspath}: the plan document nests deeper than this reader "
                   f"will descend; NOTHING was captured.",))

    stamp = captured_at
    if stamp is None:
        own = document.get("timestamp") if isinstance(document, Mapping) else None
        stamp = own if isinstance(own, str) and own else _mtime_utc(stat.st_mtime)
    return read_plan_document(document, origin=fspath, captured_at=stamp,
                              vault=vault)


def read_plan_document(document: Any, *, origin: str = "", captured_at: str = "",
                       vault: SecretVault | None = None) -> PlanRead:
    """Read one already-parsed plan (or state-representation) document.
    NEVER RAISES.

    Split from :func:`read_plan` so every gate can be exercised without a file,
    and so a caller that already holds the document reads it through the SAME
    code.
    """
    path = origin or "<document>"
    notes: list[str] = []

    if not isinstance(document, Mapping):
        return PlanRead(
            ok=False, path=origin, captured_at=captured_at,
            notes=(f"{path}: a terraform plan document is a JSON object, and this "
                   f"is a {type(document).__name__}; NOTHING was captured.",))

    raw_version = document.get("format_version")
    terraform_version = document.get("terraform_version")
    header: dict[str, Any] = {
        "path": origin,
        "captured_at": captured_at,
        "format_version": raw_version if isinstance(raw_version, str) else "",
        "terraform_version": (terraform_version
                              if isinstance(terraform_version, str) else ""),
        "errored": document.get("errored") is True,
    }

    # THE FORMAT GATE, major only. An absent `format_version` is NOTED and read
    # anyway: `terraform show -json` of a state file has been written without
    # one, and `discover` accepts that shape, so refusing it here would make a
    # file the discoverer hands over unreadable by the reader it hands it to.
    if raw_version is not None:
        major, error = _format_major(raw_version)
        if major != FORMAT_MAJOR:
            return PlanRead(
                ok=False, **header,
                notes=(FORMAT_VERSION_REFUSED.format(
                    path=path, version=raw_version, expected=FORMAT_MAJOR)
                    + (f" ({error})" if error else ""),))
    else:
        notes.append(f"{path}: the document carries no 'format_version'; it was "
                     f"read as major version {FORMAT_MAJOR} anyway, which is the "
                     f"only major this reader decodes.")

    prior = document.get("prior_state")
    changes = document.get("resource_changes")
    planned = document.get("planned_values")
    values = document.get("values")
    has_state_values = (isinstance(values, Mapping)
                        and isinstance(values.get("root_module"), Mapping))

    if prior is None and not isinstance(changes, list) \
            and not isinstance(planned, Mapping) and not has_state_values:
        return PlanRead(ok=False, notes=(NOT_A_PLAN.format(path=path),), **header)

    if header["errored"]:
        notes.append(_ERRORED_NOTE.format(path=path))

    arms: list[str] = []
    current: list[TfObject] = []
    proposed: list[TfObject] = []
    actions: dict[str, str] = {}
    entries = 0

    # -- ARM 1: prior_state, the REFRESHED read of reality ---------------------
    prior_by_address: dict[str, TfObject] = {}
    if isinstance(prior, Mapping):
        arms.append(ARM_PRIOR_STATE)
        notes.append(NEVER_COMPLETE_NOTE.format(path=path))
        prior_values = prior.get("values")
        root = prior_values.get("root_module") if isinstance(prior_values, Mapping) else None
        notes.extend(_read_outputs(
            prior_values.get("outputs") if isinstance(prior_values, Mapping) else None,
            f"{path} prior_state", vault))
        seen_prior, read_entries = _read_values_module(
            root, path=path, where="prior_state.values.root_module",
            source=PRIOR_SOURCE, origin=origin, vault=vault, notes=notes)
        entries += read_entries
        prior_by_address.update(seen_prior)
    elif prior is not None:
        notes.append(f"{path}: 'prior_state' is a {type(prior).__name__} and not an "
                     f"object; it was not read, and no current facts came from it.")
        notes.append(NO_PRIOR_STATE_NOTE.format(path=path))
    elif isinstance(changes, list) or isinstance(planned, Mapping):
        # A plan-shaped document with no prior state. NEVER fall back to
        # planned_values; say so, loudly.
        notes.append(NO_PRIOR_STATE_NOTE.format(path=path))

    # -- ARM 2: change.before, for what prior_state does not cover -------------
    before_by_address: dict[str, TfObject] = {}
    overridden: list[str] = []
    deposed_skipped: list[str] = []
    if isinstance(changes, list):
        arms.append(ARM_CHANGE_BEFORE)
        for position, entry in enumerate(changes):
            resource = _entry_identity(entry, position, path, "resource_changes",
                                       notes)
            if resource is None:
                continue
            address, rtype, name, module, index_key, provider = resource
            # A deposed generation is the OLD object a create-before-destroy
            # left behind; it is not the current object at this address, and
            # letting it contribute a before-side fact would resurrect it.
            if entry.get("deposed"):
                deposed_skipped.append(address)
                continue
            body = _change_of(entry)
            before = body.get("before")
            if before is None:
                # A pure create legitimately has no predecessor. Skipped, not
                # noted per entry: this is the normal case, and a note per
                # created resource would bury every note that matters.
                continue
            if not isinstance(before, Mapping):
                notes.append(f"{path}: {address} 'change.before' is "
                             f"{safe_repr(before)} and not an object; no current "
                             f"fact was taken from it.")
                continue
            entries += 1
            obj = _object_from_change(
                address=address, rtype=rtype, name=name, module=module,
                index_key=index_key, provider=provider, body=body, side_key="before",
                source=PRIOR_SOURCE, side="current", origin=origin,
                vault=vault, notes=notes, path=path)
            if obj is None:
                continue
            if address in prior_by_address:
                overridden.append(address)
            before_by_address[address] = obj
    if overridden:
        # THE PRECEDENCE, stated where an operator can see it: a change's
        # `before` is the exact predecessor of the exact resource under review,
        # so it outranks the same address read from the whole-workspace refresh.
        notes.append(
            f"{path}: {len(overridden)} address(es) appear in BOTH 'prior_state' "
            f"and a 'change.before' ({_sample(sorted(overridden))}); the "
            f"before-side value won, because a change's 'before' is the exact "
            f"predecessor of the exact resource under review.")
    if deposed_skipped:
        notes.append(
            f"{path}: {len(deposed_skipped)} DEPOSED change entr(y|ies) contributed "
            f"NO current fact ({_sample(sorted(deposed_skipped))}): a deposed "
            f"generation is the old object a create-before-destroy left behind, "
            f"not the object that currently occupies the address.")

    for address, obj in prior_by_address.items():
        if address not in before_by_address:
            current.append(obj)
    current.extend(before_by_address.values())

    # -- ARM 3: the PROPOSED side ---------------------------------------------
    if isinstance(changes, list) or isinstance(planned, Mapping):
        arms.append(ARM_PROPOSED)
        proposed_seen: set[str] = set()
        if isinstance(changes, list):
            # STABLY sorted so a deposed delete cannot claim an address and drop
            # the created object at that address: `sorted` is stable, so
            # non-deposed entries keep their document order and simply come
            # first.
            for position, entry in enumerate(sorted(changes, key=_is_deposed)):
                resource = _entry_identity(entry, position, path, "resource_changes",
                                           notes, quiet=True)
                if resource is None:
                    continue
                address, rtype, name, module, index_key, provider = resource
                if address in proposed_seen:
                    continue
                body = _change_of(entry)
                action, action_note = normalize_action(body.get("actions"))
                if action_note:
                    notes.append(f"{path}: {address}: {action_note}.")
                # THE DELETE RULE. `after` is null for a destroy, so without
                # this the most dangerous change a plan can carry — the removal
                # of a control — would produce no object at all.
                side_key = "after"
                object_notes: tuple[str, ...] = ()
                if body.get("after") is None:
                    if action == "delete" and isinstance(body.get("before"), Mapping):
                        side_key = "before"
                        object_notes = (
                            f"this object is what the plan REMOVES: 'after' is null "
                            f"and the action is 'delete', so its values are "
                            f"'change.before' — the deletion is a fact about what "
                            f"is being taken away, not an absence of facts.",)
                    else:
                        notes.append(
                            f"{path}: {address} has a null 'change.after' under "
                            f"action {action!r} and no readable 'before'; no "
                            f"proposed object was built for it.")
                        proposed_seen.add(address)
                        actions[address] = action
                        continue
                obj = _object_from_change(
                    address=address, rtype=rtype, name=name, module=module,
                    index_key=index_key, provider=provider, body=body,
                    side_key=side_key, source=PROPOSED_SOURCE, side="proposed",
                    origin=origin, vault=vault, notes=notes, path=path,
                    extra_notes=object_notes)
                proposed_seen.add(address)
                actions[address] = action
                if obj is not None:
                    proposed.append(obj)
        if isinstance(planned, Mapping):
            notes.extend(_read_outputs(planned.get("outputs"),
                                       f"{path} planned_values", vault))
            planned_objects, read_entries = _read_values_module(
                planned.get("root_module"), path=path,
                where="planned_values.root_module", source=PROPOSED_SOURCE,
                origin=origin, vault=vault, notes=notes, side="proposed")
            entries += read_entries
            for address, obj in planned_objects.items():
                if address in proposed_seen:
                    continue
                proposed_seen.add(address)
                # `planned_values` carries no `actions` — that vocabulary lives
                # only in `resource_changes` — so an address only it covers is
                # unchanged by this plan.
                actions.setdefault(address, "no-op")
                proposed.append(obj)

    # -- ARM 4: the bare state representation ---------------------------------
    if prior is None and not isinstance(changes, list) \
            and not isinstance(planned, Mapping) and has_state_values:
        arms.append(ARM_STATE_VALUES)
        notes.append(f"{path}: this is a 'terraform show -json' STATE "
                     f"representation, not a plan: it was read through ARM 4 "
                     f"({ARM_STATE_VALUES}) at source {STATE_SOURCE!r}.")
        notes.extend(_read_outputs(values.get("outputs"), path, vault))
        state_objects, read_entries = _read_values_module(
            values.get("root_module"), path=path, where=ARM_STATE_VALUES,
            source=STATE_SOURCE, origin=origin, vault=vault, notes=notes)
        entries += read_entries
        current.extend(state_objects.values())

    # -- resource_drift: ADDRESSES ONLY ---------------------------------------
    drift = _drift_addresses(document.get("resource_drift"), path, notes)
    if drift:
        notes.append(DRIFT_NOTE.format(count=len(drift), sample=_sample(drift)))

    if not current and not proposed:
        notes.append(NOTHING_READ_NOTE.format(path=path, entries=entries))

    logger.debug("plan %s: %d current, %d proposed, %d drift address(es), "
                 "arm(s) %s, %d note(s)", path, len(current), len(proposed),
                 len(drift), arms, len(notes))
    return PlanRead(ok=True, current=tuple(current), proposed=tuple(proposed),
                    notes=tuple(notes), drift_addresses=drift, actions=actions,
                    arms=tuple(arms), **header)


# -- the pieces ---------------------------------------------------------------


def _format_major(raw: Any) -> tuple[int | None, str]:
    """``format_version`` → ``(major, error)``. The MAJOR component ONLY."""
    if not isinstance(raw, str) or not raw:
        return None, f"'format_version' is {safe_repr(raw)}, not a version string"
    head = raw.split(".", 1)[0]
    try:
        return int(head), ""
    except ValueError:
        return None, f"'format_version' {raw!r} has no numeric major component"


def _is_deposed(entry: Any) -> bool:
    """Whether a ``resource_changes`` entry describes a deposed object — the old
    copy a create_before_destroy replacement is about to delete."""
    return isinstance(entry, Mapping) and bool(entry.get("deposed"))


def _entry_identity(entry: Any, position: int, path: str, where: str,
                    notes: list[str], *, quiet: bool = False):
    """``(address, type, name, module, index_key, provider)`` for one entry, or
    ``None`` with a note.

    ``quiet`` suppresses the note for a second pass over the SAME array, so a
    malformed entry is reported once rather than once per arm.
    """
    def refuse(reason: str) -> None:
        if not quiet:
            notes.append(f"{path}: {where}[{position}] {reason}; skipped.")

    if not isinstance(entry, Mapping):
        refuse(f"is a {type(entry).__name__} and not an object")
        return None
    mode = entry.get("mode")
    if mode is not None and mode != "managed":
        # Counted as a refusal rather than ignored: a data source IS in the
        # estate, but terraform does not manage it, so folding it into a capture
        # would overstate coverage.
        refuse(f"has mode {mode!r} and is not terraform-managed")
        return None
    address = entry.get("address")
    rtype = entry.get("type")
    name = entry.get("name")
    if not isinstance(address, str) or not address:
        refuse("carries no 'address' string")
        return None
    if not isinstance(rtype, str) or not rtype:
        refuse(f"({address}) carries no 'type' string")
        return None
    if not isinstance(name, str) or not name:
        name = address.rsplit(".", 1)[-1]
    module = entry.get("module_address") or ""
    if not isinstance(module, str):
        module = ""
    return address, rtype, name, module, entry.get("index"), _provider_name(
        entry.get("provider_name"), rtype)


def _provider_name(raw: Any, rtype: str) -> str:
    """The provider short name a plan document declares.

    Plan JSON writes ``provider_name`` as a bare SOURCE ADDRESS
    (``registry.terraform.io/hashicorp/google``) with no ``provider["..."]``
    wrapper, so the last path segment IS the provider name here — unlike a v4
    state file, where that split is the hazard that erases every google
    resource. When there is no ``provider_name`` at all, a ``google_`` type
    prefix is the only evidence there is; anything else yields ``""`` rather
    than a guess.
    """
    if isinstance(raw, str) and raw.strip():
        return raw.strip().rsplit("/", 1)[-1]
    return "google" if rtype.startswith("google_") else ""


def _read_values_module(root: Any, *, path: str, where: str, source: str,
                        origin: str, vault: SecretVault | None,
                        notes: list[str], side: str = "current",
                        ) -> tuple[dict[str, TfObject], int]:
    """Read one values-representation module tree — ``resources`` plus
    ``child_modules``, recursively — into address → object.

    ONE walker for ARM 1, ARM 3's ``planned_values`` half and ARM 4, because
    they are the same shape; three copies would be three chances to forget
    ``child_modules``, and forgetting it silently drops every resource a module
    owns.
    """
    objects: dict[str, TfObject] = {}
    entries = 0
    if root is None:
        notes.append(f"{path}: {where} is absent; nothing was read from it.")
        return objects, entries
    if not isinstance(root, Mapping):
        notes.append(f"{path}: {where} is a {type(root).__name__} and not an "
                     f"object; nothing was read from it.")
        return objects, entries
    for module_address, resource, position in _values_resources(root, ""):
        entries += 1
        identity = _entry_identity(
            resource, position, path,
            f"{where}/{module_address}" if module_address else where, notes)
        if identity is None:
            continue
        address, rtype, name, _module, index_key, provider = identity
        raw_values = resource.get("values")
        if not isinstance(raw_values, Mapping):
            notes.append(f"{path}: {address} carries no 'values' object "
                         f"({safe_repr(raw_values)}); skipped rather than read as "
                         f"empty.")
            continue
        mirror = resource.get("sensitive_values")
        redacted, redaction_notes = redact(raw_values, mirror=mirror, vault=vault)
        for note in redaction_notes:
            notes.append(f"{address}: {note}")
        if address in objects:
            notes.append(f"{path}: {where} carries TWO entries at address "
                         f"{address}; the later one was kept.")
        objects[address] = TfObject(
            address=address, type=rtype, name=name, module=module_address,
            index_key=index_key, provider=provider, source=source, side=side,
            values=redacted, sensitive_paths=mirror_paths(mirror),
            notes=tuple(redaction_notes), artifact=origin)
    return objects, entries


def _values_resources(module: Any, module_address: str,
                      depth: int = 0) -> Iterator[tuple[str, Any, int]]:
    """``(module address, resource, position)`` for every resource in a
    values-representation module tree."""
    if not isinstance(module, Mapping) or depth >= MAX_DEPTH:
        return
    resources = module.get("resources")
    if isinstance(resources, list):
        for position, resource in enumerate(resources):
            yield module_address, resource, position
    children = module.get("child_modules")
    if isinstance(children, list):
        for child in children:
            address = child.get("address") if isinstance(child, Mapping) else None
            yield from _values_resources(
                child, address if isinstance(address, str) else module_address,
                depth + 1)


def _object_from_change(*, address: str, rtype: str, name: str, module: str,
                        index_key: Any, provider: str, body: Mapping[str, Any],
                        side_key: str, source: str, side: str, origin: str,
                        vault: SecretVault | None, notes: list[str], path: str,
                        extra_notes: tuple[str, ...] = ()) -> TfObject | None:
    """Build one object from a ``change``'s ``before`` or ``after`` mapping.

    REDACTION FIRST, then the unknown marking. That order is load-bearing twice:
    a plaintext still reaches the vault (an unknown key has no value to redact
    anyway), and a ``Redacted`` is never re-digested through its own repr.
    """
    raw_values = body.get(side_key)
    if not isinstance(raw_values, Mapping):
        notes.append(f"{path}: {address} '{side_key}' is {safe_repr(raw_values)} "
                     f"and not an object; no object was built from it.")
        return None
    mirror = body.get(f"{side_key}_sensitive")
    redacted, redaction_notes = redact(raw_values, mirror=mirror, vault=vault)
    for note in redaction_notes:
        notes.append(f"{address}: {note}")
    values = _mark(redacted, body.get(f"{side_key}_unknown"), "", 0)
    unknown = mirror_paths(body.get(f"{side_key}_unknown"))
    object_notes = tuple(redaction_notes) + extra_notes
    if unknown:
        object_notes += (
            f"{len(unknown)} attribute(s) are (known after apply) and were CREATED "
            f"as 'unknown_after_apply' markers ({_sample(unknown)}); an unknown "
            f"attribute is omitted from '{side_key}' entirely, so a missing key "
            f"would otherwise read as unset.",)
    return TfObject(
        address=address, type=rtype, name=name, module=module,
        index_key=index_key, provider=provider, source=source, side=side,
        values=values, sensitive_paths=mirror_paths(mirror),
        unresolved=_markers(values), notes=object_notes, artifact=origin)


def _markers(values: Any) -> tuple[Unresolved, ...]:
    """The flat roll-up of every marker in *values*, in path order."""
    return tuple(marker for _path, marker in unresolved_in(values))


def _drift_addresses(drift: Any, path: str, notes: list[str]) -> tuple[str, ...]:
    """``resource_drift`` → its addresses, in document order. NEVER objects."""
    if drift is None:
        return ()
    if not isinstance(drift, list):
        notes.append(f"{path}: 'resource_drift' is a {type(drift).__name__} and "
                     f"not an array; no drift addresses were recorded.")
        return ()
    addresses: list[str] = []
    for position, entry in enumerate(drift):
        address = entry.get("address") if isinstance(entry, Mapping) else None
        if isinstance(address, str) and address:
            addresses.append(address)
        else:
            notes.append(f"{path}: resource_drift[{position}] carries no 'address' "
                         f"string; it could not be reported to the operator.")
    return tuple(addresses)


def _read_outputs(outputs: Any, path: str, vault: SecretVault | None) -> list[str]:
    """Read ``outputs`` ONLY far enough to say that a sensitive one exists.

    An output value is stored in PLAINTEXT and the ``sensitive`` flag is a
    display marker, so the value is never returned, never logged and never
    noted — only the NAME is. When a vault is supplied the plaintext is handed
    to it, which is what lets the final scrub catch the value if some other
    module later renders it.
    """
    if outputs is None:
        return []
    if not isinstance(outputs, Mapping):
        return [f"{path}: 'outputs' is a {type(outputs).__name__} and not an "
                f"object; it was not read."]
    sensitive: list[str] = []
    for name, body in sorted(outputs.items(), key=lambda item: str(item[0])):
        if isinstance(body, Mapping) and body.get("sensitive") is True:
            sensitive.append(str(name))
            if vault is not None:
                value = body.get("value")
                if isinstance(value, str):
                    vault.add(value)
    if not sensitive:
        return []
    return [f"{path}: {len(sensitive)} of {len(outputs)} output(s) are marked "
            f"sensitive ({_sample(sensitive)}) and terraform writes their values "
            f"in PLAINTEXT — the flag is a DISPLAY marker only. Outputs are not "
            f"read as facts here; only their names appear."]


def _sample(items: Sequence[str], limit: int = 5) -> str:
    """Name the first few; a note that says only "12 were skipped" is a note
    nobody can act on."""
    shown = ", ".join(items[:limit])
    extra = len(items) - limit
    return f"{shown} and {extra} more" if extra > 0 else shown


# -- onto the ledger ----------------------------------------------------------


def drift_note(read: PlanRead) -> str:
    """The ``resource_drift`` note for *read*, or ``""`` when nothing drifted.

    THE ONE rendering of it, so the reader's note, the ledger's source record
    and the aggregate ``drift`` verdict cannot describe the same drift three
    different ways.
    """
    if not read.drift_addresses:
        return ""
    return DRIFT_NOTE.format(count=len(read.drift_addresses),
                             sample=_sample(read.drift_addresses))


def source_record(read: PlanRead, *, source_id: str = "",
                  scope: str = "partial", boundary: str = "") -> SourceRecord:
    """The :class:`gcp_grounding.provenance.SourceRecord` for this plan
    artifact, CARRYING the drift addresses as its note.

    This is how terraform's own detected drift reaches an operator: a note that
    stops at the reader is invisible to the agent, and drift is exactly the
    signal a human wants. ``serial`` and ``lineage`` are deliberately absent —
    they are terraform STATE identity, and a plan has none.

    The scope defaults to ``partial`` and ``SourceRecord`` caps a terraform kind
    there anyway; nothing here can declare a plan complete.
    """
    return SourceRecord(
        source_id=source_id or read.path or "tfplan",
        kind=PRIOR_SOURCE, origin=read.path, captured_at=read.captured_at,
        scope=scope, boundary=boundary, note=drift_note(read))


# -- the ONE claims path ------------------------------------------------------


def as_plan_document(entries: Iterable[TfObject]) -> dict[str, Any]:
    """Render terraform objects as the plan document
    :func:`gcp_grounding.tf_claims.terraform_plan_claims` reads.

    **NORMATIVE.** ANY terraform reader in this tree turns resources into claims
    by building THIS document and calling ``tf_claims.terraform_plan_claims``.
    That one call inherits the WHOLE dispatch table — the five built-in
    extractors, every provider extractor registered later through
    ``registry.tf_extractors``, and the conservative skip discipline that makes
    an ambiguous field yield no claim rather than a guess. **Writing a second
    extraction path is FORBIDDEN**: a second implementation of a load-bearing
    rule is a second place for it to be wrong, silently, and the one that is
    wrong will be the one nobody is looking at. ``tests/test_gcp_claims_tf.py``
    is frozen to prove the existing path is untouched.

    Every object is emitted at ``mode: "managed"``, which is the only mode this
    reader keeps, into ``planned_values.root_module.resources`` as ONE flat list
    in the order given — the claim walker reads that list in document order, so
    the caller's order is the claim order. ``values`` are passed through exactly
    as the reader built them, markers and redactions included: an extractor that
    meets one degrades through ``terraform_plan_claims``' never-raise contract
    to "only its type reference is claimed", which is the honest answer for an
    attribute nobody has seen.
    """
    resources: list[dict[str, Any]] = []
    for obj in entries:
        resource: dict[str, Any] = {
            "address": obj.address,
            "mode": "managed",
            "type": obj.type,
            "name": obj.name or obj.address.rsplit(".", 1)[-1],
            "values": obj.values,
        }
        if obj.index_key is not None:
            resource["index"] = obj.index_key
        if obj.provider:
            # Omitted when the reader could not attribute one, so the claim
            # walker falls back to its own `google_` prefix test rather than
            # being handed a provider nobody wrote.
            resource["provider_name"] = obj.provider
        resources.append(resource)
    return {
        "format_version": f"{FORMAT_MAJOR}.0",
        "planned_values": {"root_module": {"resources": resources}},
    }
