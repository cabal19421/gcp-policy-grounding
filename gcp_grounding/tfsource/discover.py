"""Find terraform artifacts in a tree and say which is which — BY CONTENT.

Layer 1, step 1 of the pipeline described in :mod:`gcp_grounding.tfsource`.
Nothing here parses terraform semantics; this module answers exactly two
questions — *is this file a terraform artifact* and *which kind* — and hands
the answer, with a :class:`gcp_grounding.provenance.ArtifactRef`, to the reader
that owns that kind.

THE ``terraform_version`` TRAP
------------------------------
:func:`gcp_grounding.preflight.detect_kind` classifies a v4 ``.tfstate`` as a
terraform PLAN. Its plan-key set is ``("format_version", "terraform_version",
"planned_values", "resource_changes")`` and it returns ``tf_plan`` if ANY of
them is present — and ``terraform_version`` is a top-level key of every single
tfstate ever written. A state file therefore detects as a plan, extracts zero
claims, and prints a clean-looking pass: the worst possible answer for a
document describing an entire estate.

The rule this module enforces, in one sentence: **``detect_kind`` may be
consulted only to EXPLAIN a rejection and may never decide a positive
classification here.** It is imported lazily, inside
:func:`_detector_opinion`, and its answer only ever appends a clause to a
``reason`` string. Fixing the detector belongs to whoever owns
``preflight.py``; defending against it is this module's job.

CLASSIFICATION IS BY CONTENT, with ONE exception
------------------------------------------------
Every arm below inspects the PARSED DOCUMENT, never the file name — a name is
a convention and a convention is what an attacker, a generator or a tired
human breaks. The single exception is HCL: raw HCL has no sniffable header, no
version key and no envelope, so a ``.tf`` file is HCL by extension and there is
no other way to know. ``.tf.json`` inherits the same exception because it is
HCL written in JSON syntax — but its CONTENT is still checked for one of the
terraform block keywords, so a ``.tf.json`` that holds something else is
refused rather than handed to the HCL reader.

THE SHARED v4 SNIFF AND THE SHARED MESSAGE
------------------------------------------
:func:`is_v4_state` and :data:`STATE_NOT_A_PROPOSAL` are exported from here
because two OTHER entry points need them — the gate's proposal router and the
CLI's ``verify-policy`` positional argument — and both must catch a state file
before ``detect_kind`` turns it into a zero-claim clean pass. Both import them
lazily behind the established ``ImportError`` fail-open idiom and both assert
their emitted message is EQUAL to the shared constant. Three hand-written
``version == 4`` tests would be three places to drift, and a drifted sniff is
exactly the silent pass those two entry points exist to close. The ``tfstate``
arm below calls :func:`is_v4_state` itself rather than repeating the test.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..core.log import get_logger
from ..facts import PROPOSED_SOURCES
from ..provenance import SOURCES, ArtifactRef

logger = get_logger(__name__)

__all__ = [
    "ARTIFACT_KINDS",
    "CLASSIFICATION_ORDER",
    "SOURCE_FOR_KIND",
    "PROPOSED_SOURCE_FOR_KIND",
    "HCL_BLOCK_KEYS",
    "PRUNE_DIRS",
    "CANDIDATE_SUFFIXES",
    "BACKUP_SUFFIX",
    "MAX_ARTIFACT_BYTES",
    "STATE_NOT_A_PROPOSAL",
    "REMOTE_BACKEND_STUB",
    "is_v4_state",
    "Artifact",
    "Discovery",
    "classify_path",
    "discover",
]

#: Every artifact kind this package can read. A kind is a READER dispatch key,
#: not a source spelling: two kinds map onto one source (``tfstate`` and
#: ``state_json`` are the same estate in two encodings) and the translation is
#: :data:`SOURCE_FOR_KIND`.
ARTIFACT_KINDS = ("plan_json", "state_json", "tfstate", "hcl", "hcl_json")

#: THE NORMATIVE ORDER the arms are tried in. It is load-bearing twice over:
#:
#: - ``tfstate`` runs before ``plan_json``. That is the structural inversion of
#:   the ``terraform_version`` trap: the plan-shaped keys are checked LAST, not
#:   first, so a state file can never fall into a plan arm.
#: - ``state_json`` runs before ``plan_json``. ``terraform show -json`` of a
#:   STATE file emits a ``format_version`` too, so a plan-first order would
#:   refuse every state representation for lacking a ``prior_state`` it was
#:   never going to have.
CLASSIFICATION_ORDER = ("hcl", "hcl_json", "tfstate", "state_json", "plan_json")

#: Kind → the ONE ``provenance.SOURCES`` spelling for the CURRENT-state side.
#: ``state_json`` collapses onto ``tfstate`` because it IS state, re-encoded by
#: ``terraform show``; a plan contributes only the refreshed prior read, which
#: is narrower than state and is spelled ``tfplan-prior``.
SOURCE_FOR_KIND = {
    "plan_json": "tfplan-prior",
    "state_json": "tfstate",
    "tfstate": "tfstate",
    "hcl": "hcl",
    "hcl_json": "hcl",
}

#: Kind → the ``facts.PROPOSED_SOURCES`` spelling for the PROPOSED side.
#: ``tfstate`` and ``state_json`` map to NOTHING and are absent from this map on
#: purpose: a state file records what already exists, so it is never a proposal
#: and there is no spelling under which it could become one.
PROPOSED_SOURCE_FOR_KIND = {
    "plan_json": "tfplan-planned",
    "hcl": "hcl-proposed",
    "hcl_json": "hcl-proposed",
}

def _check_translation_maps() -> None:
    """These two maps are the ONLY kind-to-source translation anywhere in this
    package; there is no private tier tuple beside them. Run at import, and by
    ``raise`` rather than ``assert`` so ``python -O`` cannot strip the one check
    standing between a typo and a fact stamped with a source no ranking
    function recognises."""
    if set(SOURCE_FOR_KIND) != set(ARTIFACT_KINDS):
        raise ValueError(f"SOURCE_FOR_KIND must be total over {list(ARTIFACT_KINDS)}")
    stray = set(SOURCE_FOR_KIND.values()) - set(SOURCES)
    if stray:
        raise ValueError(f"SOURCE_FOR_KIND names {sorted(stray)}, which is not "
                         f"in provenance.SOURCES")
    stray = set(PROPOSED_SOURCE_FOR_KIND) - set(ARTIFACT_KINDS)
    if stray:
        raise ValueError(f"PROPOSED_SOURCE_FOR_KIND names non-kind(s) {sorted(stray)}")
    stray = set(PROPOSED_SOURCE_FOR_KIND.values()) - set(PROPOSED_SOURCES)
    if stray:
        raise ValueError(f"PROPOSED_SOURCE_FOR_KIND names {sorted(stray)}, which "
                         f"is not in facts.PROPOSED_SOURCES")
    stray = {"tfstate", "state_json"} & set(PROPOSED_SOURCE_FOR_KIND)
    if stray:
        raise ValueError(f"{sorted(stray)} has a proposed spelling; a state file "
                         f"records what exists and is never a proposal")


_check_translation_maps()

#: Top-level keywords a terraform JSON configuration may carry. A ``.tf.json``
#: with none of them is not configuration, whatever it is named.
HCL_BLOCK_KEYS = ("resource", "data", "module", "variable", "locals",
                  "provider", "output", "terraform")

#: Directories a walk prunes IN PLACE, enumerated rather than described because
#: an unnamed ignore list is one an implementer writes from memory.
#:
#: ``.terraform`` is the load-bearing member. With a ``gcs`` or ``s3`` backend
#: the file under it holds only the backend configuration ``init`` recorded, has
#: no ``resources`` array, and looks IDENTICAL to a clean empty estate — see
#: :data:`REMOTE_BACKEND_STUB`. A walk that descends into ``.git`` or
#: ``.terraform`` picks up exactly the blobs and stubs every other arm here
#: exists to reject.
PRUNE_DIRS = (".git", ".terraform", "node_modules", "__pycache__", ".venv",
              ".pytest_cache")

#: The state-backup suffix. A backup is the estate as it was BEFORE the last
#: apply, so it is refused unless the caller opts in by name.
BACKUP_SUFFIX = ".tfstate.backup"

#: Suffixes a WALK considers worth opening. This is a candidate filter, not a
#: classification: everything that survives it is still classified by content.
#: Without it, every README and lockfile in a repository becomes a rejection
#: record and the real findings drown.
CANDIDATE_SUFFIXES = (".tf", ".tf.json", ".json", ".tfstate", BACKUP_SUFFIX)

#: Biggest artifact this tool will open. A state file for a large estate is a
#: few megabytes; something two orders of magnitude past that is a mistake, a
#: log or a bomb, and reading it into memory inside a pre-commit gate is how a
#: gate becomes a denial of service.
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

#: THE ONE MESSAGE for "this is Terraform state, not a proposed change",
#: parameterised by path. Rendered with ``.format(path=...)`` by this module,
#: by the gate's proposal router and by the CLI's ``verify-policy`` argument —
#: the same string in all three, so no entry point can say something different
#: about the same file.
STATE_NOT_A_PROPOSAL = (
    "{path}: this is Terraform state, not a proposed change. State records "
    "what already EXISTS, so it is a CURRENT-state source; it was not graded "
    "as a proposal, because grading it would report the whole estate as if an "
    "agent had just written it. Pass it with the terraform-state flag, or "
    "list it as a state source in the config file, to use it as a baseline "
    "for other edits."
)

#: THE REMOTE-BACKEND STUB message, parameterised by path. The file ``init``
#: writes under ``.terraform`` for a remote backend holds the backend
#: configuration and NOTHING else — no ``resources`` array — which is
#: byte-for-byte as convincing as a clean empty estate.
REMOTE_BACKEND_STUB = (
    "{path}: this is a Terraform remote-backend stub, not state — it records "
    "where state lives and NOTHING was captured in it, so reading it would "
    "report an empty estate that is indistinguishable from a real one. Fetch "
    "the real state out of band with a terraform state pull and point at the "
    "file that produces; this tool never fetches anything."
)


# -- the shared v4 sniff ------------------------------------------------------


def is_v4_state(doc: Any) -> bool:
    """True if *doc* is a version-4 Terraform state document.

    THE ONE PREDICATE. A ``version`` of exactly 4, a ``lineage`` key and a
    ``resources`` list — all three, because ``version`` alone is carried by an
    IAM policy, ``lineage`` alone by the backend stub, and a missing
    ``resources`` array is precisely the stub that reads as an empty estate.

    The ``tfstate`` arm of :func:`classify_path` calls THIS, and the gate and
    the CLI import it lazily rather than writing a fourth ``version == 4``.
    """
    if not isinstance(doc, Mapping):
        return False
    return (doc.get("version") == 4
            and "lineage" in doc
            and isinstance(doc.get("resources"), list))


# -- the records --------------------------------------------------------------


@dataclass(frozen=True)
class Artifact:
    """One candidate, classified. Either ACCEPTED with a kind or REJECTED with
    a reason, never both and never neither.

    A rejection is a first-class result rather than an omission: ``tx-tf-cli``
    prints why each candidate was refused, and a candidate that vanished
    silently is a candidate the user believes was read.
    """

    path: str
    kind: str = ""
    source: str = ""
    proposed_source: str = ""
    reason: str = ""
    ref: ArtifactRef | None = None

    def __post_init__(self) -> None:
        if not self.path:
            raise ValueError("Artifact.path must name the file classified")
        if self.kind:
            if self.kind not in ARTIFACT_KINDS:
                raise ValueError(f"Artifact.kind {self.kind!r} is not one of "
                                 f"{list(ARTIFACT_KINDS)}")
            if self.reason:
                raise ValueError(f"Artifact({self.path!r}) carries both a kind "
                                 f"and a rejection reason; it is one or the other")
        elif not self.reason:
            raise ValueError(f"Artifact({self.path!r}) was neither classified "
                             f"nor rejected — a refusal without a reason is a "
                             f"file the caller believes was read")

    @property
    def accepted(self) -> bool:
        return bool(self.kind)

    @property
    def rejected(self) -> bool:
        return not self.kind


@dataclass(frozen=True)
class Discovery:
    """What one walk found: the accepted artifacts, the refused candidates and
    the walk-level notes. Both tuples are sorted by path, so two runs over an
    unchanged tree produce identical output."""

    root: str = ""
    artifacts: tuple[Artifact, ...] = ()
    rejected: tuple[Artifact, ...] = ()
    notes: tuple[str, ...] = ()

    def by_kind(self, kind: str) -> tuple[Artifact, ...]:
        return tuple(a for a in self.artifacts if a.kind == kind)

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(a.path for a in self.artifacts)


def _accept(path: str, kind: str) -> Artifact:
    """Build the accepted record, fingerprinting through ``ArtifactRef.of`` —
    the one definition of how an artifact is hashed, so no two writers in this
    repo can hash the same bytes differently."""
    source = SOURCE_FOR_KIND[kind]
    return Artifact(path=path, kind=kind, source=source,
                    proposed_source=PROPOSED_SOURCE_FOR_KIND.get(kind, ""),
                    ref=ArtifactRef.of(path, kind=kind, source=source))


def _reject(path: str, reason: str) -> Artifact:
    logger.debug("discover: refused %s: %s", path, reason)
    return Artifact(path=path, reason=reason)


# -- the detector's opinion, for EXPLANATIONS only ----------------------------


def _detector_opinion(doc: Any) -> str:
    """A trailing clause naming what ``preflight.detect_kind`` makes of *doc*.

    This is the ONLY call to the detector in this package and it can only ever
    lengthen a rejection message. Imported lazily behind ``ImportError`` so
    this module stays importable — and this package stays cheap — regardless of
    what ``preflight`` happens to drag in.
    """
    try:
        from ..preflight import detect_kind
    except ImportError:                                   # pragma: no cover
        return ""
    try:
        kind = detect_kind(doc)
    except Exception:                                     # pragma: no cover
        return ""
    if kind is None:
        return " No policy-document kind was recognised in it either."
    return (f" The policy detector reads it as {kind!r}, which is a PROPOSAL "
            f"kind: this file belongs on the document-under-review side, not "
            f"on the current-state side.")


# -- the arms -----------------------------------------------------------------


def _format_version_major(doc: Mapping[str, Any]) -> tuple[int | None, str]:
    """→ ``(major, error)``. Exactly one is meaningful. The MAJOR component
    only: pinning a minor would refuse next month's terraform for no reason."""
    raw = doc.get("format_version")
    if not isinstance(raw, str) or not raw:
        return None, (f"its 'format_version' is {raw!r}, which is not a "
                      f"version string")
    head = raw.split(".", 1)[0]
    try:
        return int(head), ""
    except ValueError:
        return None, f"its 'format_version' {raw!r} has no numeric major component"


def _state_shaped(doc: Mapping[str, Any]) -> bool:
    """Whether *doc* is trying to be a state file at all.

    Deliberately narrow. ``lineage``, ``serial``, ``backend`` and ``modules``
    are tfstate/stub vocabulary and appear in no policy document; a bare
    ``version`` is NOT enough, because an IAM allow policy carries
    ``version: 3`` and must not be refused as a stale state file.
    """
    if any(key in doc for key in ("lineage", "serial", "backend", "modules")):
        return True
    return "version" in doc and "resources" in doc


def _classify_tfstate(path: str, doc: Mapping[str, Any]) -> Artifact | None:
    """The ``tfstate`` arm. None means *not my shape, try the next arm*."""
    if is_v4_state(doc):
        return _accept(path, "tfstate")
    if not _state_shaped(doc):
        return None
    version = doc.get("version")
    resources = doc.get("resources")
    # The stub is checked before the version refusal: `init` stamps it with a
    # version of its own, so "wrong version" would be a true statement that
    # sends the user looking in entirely the wrong place.
    if "backend" in doc and not isinstance(resources, list):
        return _reject(path, REMOTE_BACKEND_STUB.format(path=path))
    if version != 4:
        return _reject(
            path,
            f"{path}: this is Terraform state version {version!r}, and only "
            f"version 4 is readable here. It is REFUSED rather than read "
            f"partially, because a state file this reader cannot decode "
            f"yields zero resources, and zero resources is indistinguishable "
            f"from a clean empty estate. Migrate it to version 4 with a "
            f"current terraform before capturing it.")
    if not isinstance(resources, list):
        return _reject(path, REMOTE_BACKEND_STUB.format(path=path))
    return _reject(path, f"{path}: this is a version-4 state envelope with no "
                         f"'lineage', so it cannot be attributed to a state "
                         f"history and two captures of it cannot be told apart.")


def _classify_state_json(path: str, doc: Mapping[str, Any]) -> Artifact | None:
    """The ``terraform show -json`` STATE representation arm."""
    values = doc.get("values")
    if not isinstance(values, Mapping) or "root_module" not in values:
        return None
    if "resource_changes" in doc or "prior_state" in doc:
        return None                       # that is a plan; the next arm owns it
    if "format_version" in doc:
        major, error = _format_version_major(doc)
        if major is None or major != 1:
            return _reject(path, _unknown_major(path, doc, error, "state"))
    return _accept(path, "state_json")


def _classify_plan_json(path: str, doc: Mapping[str, Any]) -> Artifact | None:
    """The plan arm — the ONLY arm that reads plan-shaped keys, and the LAST
    one tried."""
    if "format_version" not in doc:
        return None
    major, error = _format_version_major(doc)
    if major is None or major != 1:
        return _reject(path, _unknown_major(path, doc, error, "plan"))
    # A plan earns its place on the CURRENT-state side through `prior_state`
    # and nothing else: SOURCE_FOR_KIND maps this kind onto `tfplan-prior`, the
    # REFRESHED read of reality that plan performed. A plan without one carries
    # only `resource_changes` — a description of what SOMEONE WANTS TO HAPPEN.
    # Taking it as a source is exactly the failure this arm exists to prevent:
    # a proposal promoted to evidence grounds a change against itself and
    # every widening check it should have caught passes.
    if "prior_state" not in doc:
        return _reject(
            path,
            f"{path}: this is a Terraform plan with no 'prior_state', so it "
            f"describes only what is PROPOSED and carries no reading of what "
            f"currently exists. It is refused as a current-state source — "
            f"accepting it would ground a change against itself. Pass it as "
            f"the document under review instead, or re-run terraform plan "
            f"with a refresh so it carries prior state.")
    return _accept(path, "plan_json")


def _unknown_major(path: str, doc: Mapping[str, Any], error: str,
                   what: str) -> str:
    if error:
        return (f"{path}: this looks like terraform {what} JSON, but {error}. "
                f"It is refused rather than guessed at.")
    return (f"{path}: this is terraform {what} JSON in format version "
            f"{doc.get('format_version')!r}. Only major version 1 is "
            f"understood here, and an unknown major is REFUSED rather than "
            f"read against a schema it may not follow — a misread plan is a "
            f"confident answer about the wrong document.")


# -- classify one path --------------------------------------------------------


def _hcl_json_name(path: str) -> bool:
    return path.endswith(".tf.json")


def _hcl_name(path: str) -> bool:
    return path.endswith(".tf")


def classify_path(path: str | os.PathLike[str], *,
                  include_backups: bool = False,
                  max_bytes: int = MAX_ARTIFACT_BYTES) -> Artifact:
    """Classify one file. NEVER RAISES.

    An unreadable file, an oversize one, undecodable bytes and a
    ``RecursionError`` from pathological nesting each come back as a rejection
    record carrying the reason — a discoverer that throws inside a walk is a
    discoverer that loses every artifact after the bad one.
    """
    fspath = os.fspath(path)

    if fspath.endswith(BACKUP_SUFFIX) and not include_backups:
        return _reject(fspath, f"{fspath}: this is a terraform state BACKUP, "
                               f"which is the estate as it was BEFORE the last "
                               f"apply. Reading it as current state grounds "
                               f"today's change against yesterday's world; opt "
                               f"in explicitly if that is what you meant.")

    try:
        size = os.path.getsize(fspath)
        if size > max_bytes:
            return _reject(fspath, f"{fspath}: the file is {size} bytes, over "
                                   f"the {max_bytes}-byte artifact limit, and "
                                   f"was not opened.")
        with open(fspath, "rb") as fh:
            payload = fh.read(max_bytes + 1)
    except OSError as exc:
        return _reject(fspath, f"{fspath}: the file could not be read ({exc}) "
                               f"— nothing was classified.")
    if len(payload) > max_bytes:
        return _reject(fspath, f"{fspath}: the file grew past the "
                               f"{max_bytes}-byte artifact limit while it was "
                               f"being read, and was not classified.")

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        return _reject(fspath, f"{fspath}: the file is not UTF-8 text ({exc}) "
                               f"— no terraform artifact is binary, so it was "
                               f"not classified.")

    # ARM 1, the one filename exception. Raw HCL has no version key, no
    # envelope and no sniffable header of any kind, so extension is the only
    # signal there is. `.tf.json` is excluded here and handled by ARM 2.
    if _hcl_name(fspath) and not _hcl_json_name(fspath):
        return _accept(fspath, "hcl")

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        if _hcl_json_name(fspath):
            return _reject(fspath, f"{fspath}: a .tf.json must be JSON and "
                                   f"this does not parse ({exc}) — terraform "
                                   f"would refuse it too.")
        return _reject(fspath, f"{fspath}: not valid JSON ({exc}) and not a "
                               f".tf file, so it is no terraform artifact.")
    except RecursionError:
        return _reject(fspath, f"{fspath}: the document nests deeper than this "
                               f"reader will descend, so it was refused rather "
                               f"than crashing the walk. A terraform artifact "
                               f"is not nested this deep.")

    if not isinstance(doc, Mapping):
        return _reject(fspath, f"{fspath}: the document is a "
                               f"{type(doc).__name__}, and every terraform "
                               f"artifact is a JSON object.")

    # ARM 2, the second half of the HCL exception: terraform JSON configuration.
    # The NAME routes it here, but the CONTENT still has to carry a terraform
    # block keyword, so a `.tf.json` holding something else is refused.
    if _hcl_json_name(fspath):
        if any(key in doc for key in HCL_BLOCK_KEYS):
            return _accept(fspath, "hcl_json")
        return _reject(fspath, f"{fspath}: a .tf.json carrying none of "
                               f"{list(HCL_BLOCK_KEYS)} is not terraform "
                               f"configuration, whatever it is named."
                               + _detector_opinion(doc))

    # ARMS 3-5, by CONTENT, in CLASSIFICATION_ORDER.
    for arm in (_classify_tfstate, _classify_state_json, _classify_plan_json):
        verdict = arm(fspath, doc)
        if verdict is not None:
            return verdict

    return _reject(fspath, f"{fspath}: no terraform artifact arm matched its "
                           f"content — it is none of "
                           f"{list(ARTIFACT_KINDS)}." + _detector_opinion(doc))


# -- walk a tree --------------------------------------------------------------


def _is_candidate(name: str) -> bool:
    """Worth opening. A ``.tfstate.backup`` IS a candidate even when backups
    are not opted in, so the walk reports it as a REFUSED artifact naming the
    reason rather than dropping it silently — a file the user can see in the
    directory and cannot see in the output reads as a file that was read."""
    return any(name.endswith(suffix) for suffix in CANDIDATE_SUFFIXES)


def discover(root: str | os.PathLike[str], *,
             follow_symlinks: bool = False,
             include_backups: bool = False,
             max_bytes: int = MAX_ARTIFACT_BYTES) -> Discovery:
    """Walk *root* and classify every candidate under it.

    ``follow_symlinks`` is named rather than implied so the default — DO NOT
    FOLLOW — is visible at every call site: a symlink out of the tree is how a
    walk scoped to one repository ends up reading someone else's estate.
    :data:`PRUNE_DIRS` is pruned in place, so nothing under them is even
    stat'ed. Both result tuples are sorted by path.
    """
    fsroot = os.fspath(root)
    accepted: list[Artifact] = []
    refused: list[Artifact] = []
    notes: list[str] = []

    if os.path.isfile(fsroot):
        candidates: list[str] = [fsroot]
    else:
        candidates = list(_walk(fsroot, follow_symlinks, notes))

    for candidate in candidates:
        artifact = classify_path(candidate, include_backups=include_backups,
                                 max_bytes=max_bytes)
        (accepted if artifact.accepted else refused).append(artifact)

    accepted.sort(key=lambda a: a.path)
    refused.sort(key=lambda a: a.path)
    logger.debug("discover(%s): %d artifact(s), %d refused", fsroot,
                 len(accepted), len(refused))
    return Discovery(root=fsroot, artifacts=tuple(accepted),
                     rejected=tuple(refused), notes=tuple(notes))


def _walk(fsroot: str, follow_symlinks: bool,
          notes: list[str]) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(fsroot,
                                                followlinks=follow_symlinks):
        pruned = [name for name in dirnames if name in PRUNE_DIRS]
        # IN PLACE: os.walk only honours a mutation of the existing list.
        dirnames[:] = sorted(name for name in dirnames
                             if name not in PRUNE_DIRS)
        if not follow_symlinks:
            kept = []
            for name in dirnames:
                if os.path.islink(os.path.join(dirpath, name)):
                    notes.append(f"{os.path.join(dirpath, name)}: symbolic "
                                 f"link not followed")
                else:
                    kept.append(name)
            dirnames[:] = kept
        for name in sorted(pruned):
            notes.append(f"{os.path.join(dirpath, name)}: pruned, "
                         f"{name} never holds a readable estate")
        for name in sorted(filenames):
            if not _is_candidate(name):
                continue
            full = os.path.join(dirpath, name)
            if not follow_symlinks and os.path.islink(full):
                notes.append(f"{full}: symbolic link not followed")
                continue
            yield full
