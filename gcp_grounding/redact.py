"""The ONE secret boundary in the tree: value-derived redaction, a serialisable
wire form, and a handler-level log filter that heals itself.

There are TWO acceptance bars here and the second is as load-bearing as the
first.

**One: a known secret never appears** on stdout, on stderr, in any log record,
in any verdict message or in any sidecar.

**Two: two DIFFERENT secrets never render identically.** A constant mask
(``"***"``) satisfies the first bar and violates the second, and violating the
second silently suppresses every drift finding on a sensitive field — the two
redacted documents compare EQUAL, no dispute is produced, and no check ever
learns that the two sources disagreed. That is why the replacement is a
:class:`Redacted` carrying a salted digest of the value and not a constant.

Layering: this is a LAYER 0 vocabulary module. It imports the standard library,
``core.log`` and :mod:`gcp_grounding.facts` (its sibling at the same layer) and
nothing else — no snapshot, no I/O, no clock. ``core/log.py``, ``knowledge.py``,
``fetch.py`` and everything under ``core/`` are on the never-edit list and are
not touched by this module; the log filter below exists precisely because
``core/log.py`` may not be edited to grow one.

Three things live here and nowhere else:

- :class:`Redacted`, the ONE replacement type, plus its wire spelling;
- :func:`redact`, the ONE entry point, with its three detection routes;
- :class:`SecretVault` and the log filter, the final scrub for anything that
  escaped attribute-level replacement (an interpolated fragment, a message
  built by hand, a value logged before the reader reached it).
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Mapping, NamedTuple, Sequence

from .core.log import get_logger
from .facts import MAX_DEPTH, safe_repr

logger = get_logger(__name__)

__all__ = [
    "DEFAULT_REDACT_SALT",
    "SALT_ENV",
    "DIGEST_LEN",
    "WIRE_PREFIX",
    "MIN_SECRET_LEN",
    "SENSITIVE_PATTERNS",
    "NEVER_SENSITIVE_SUFFIXES",
    "Redacted",
    "RedactResult",
    "current_salt",
    "value_digest",
    "is_wire",
    "is_sensitive_segment",
    "redact",
    "redact_cty_paths",
    "redact_mirror",
    "redact_by_name",
    "redacted_in",
    "has_redacted",
    "to_wire",
    "SecretVault",
    "SecretScrubFilter",
    "scrub_record",
    "scrub_verdict",
    "scrub_verdicts",
    "scrub_report",
    "install_log_filter",
    "ensure_log_filter",
    "remove_log_filter",
]


# -- the digest ---------------------------------------------------------------

#: Environment variable naming the salt. An operator who shares sidecars
#: outside the team SHOULD set this to a team secret.
SALT_ENV = "GCP_GROUNDING_REDACT_SALT"

#: The fallback salt, a FIXED documented ASCII string.
#:
#: **It is fixed on purpose and must never be randomised per process.** A
#: per-process salt makes digests incomparable across runs: every
#: capture-then-verify round trip would report a phantom ``drift:material`` on
#: every sensitive field, and two sources that AGREE on a secret would be
#: reported as disagreeing. Comparability across processes IS the feature.
#:
#: **The dictionary-attack caveat.** With a known salt, a SHORT low-entropy
#: secret is recoverable by anyone who can guess candidates and hash them —
#: ``"hunter2"`` digests to the same 16 hex characters everywhere this default
#: is in force. That is why :data:`SALT_ENV` exists, why an operator who
#: circulates sidecars outside the team must set their own salt, and why a
#: digest is NOT a substitute for not putting secrets into terraform state in
#: the first place. The digest makes a leaked artifact useless for lateral
#: movement; it does not make a weak secret strong.
DEFAULT_REDACT_SALT = "gcp-policy-grounding/redact/v1"

#: Hex characters of the sha256 kept. 16 hex characters is 64 bits — small
#: enough to read in a report line, wide enough that two DIFFERENT sensitive
#: values colliding (and so being reported as agreeing) is not a practical
#: failure mode for an estate-sized document.
DIGEST_LEN = 16

#: The serialised spelling's fixed prefix. The algorithm is named in the wire
#: form so a future widening stays parseable rather than ambiguous.
WIRE_PREFIX = "redacted:sha256:"

_WIRE_RE = re.compile(r"^redacted:sha256:([0-9a-f]{%d})$" % DIGEST_LEN)


def current_salt() -> str:
    """The salt in force RIGHT NOW: :data:`SALT_ENV` if set and non-empty,
    else :data:`DEFAULT_REDACT_SALT`.

    Read at call time rather than at import time so a test (or a CLI that sets
    the variable after import) gets the salt it asked for.
    """
    return os.environ.get(SALT_ENV) or DEFAULT_REDACT_SALT


def _as_text(value: Any) -> str:
    """The exact bytes a value is digested over.

    A ``str`` is itself; every other shape is rendered as canonical JSON with
    sorted keys, so the SAME container from two differently-ordered readers
    digests identically — otherwise the digest would report drift that is only
    dict ordering.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)
    except (TypeError, ValueError):          # pragma: no cover - defensive
        return repr(value)


def value_digest(value: Any, *, salt: str | None = None) -> str:
    """sha256 over ``salt``, a NUL byte and the UTF-8 value, truncated to
    :data:`DIGEST_LEN` hex characters.

    The NUL separator is what stops ``salt="ab", value="c"`` and
    ``salt="a", value="bc"`` from colliding: without it a salt change could
    make two different secrets digest the same.
    """
    key = (current_salt() if salt is None else salt).encode("utf-8")
    body = _as_text(value).encode("utf-8")
    return hashlib.sha256(key + b"\x00" + body).hexdigest()[:DIGEST_LEN]


# -- the one replacement type -------------------------------------------------


@dataclass(frozen=True, eq=False, repr=False)
class Redacted:
    """A sensitive value, replaced at the loading boundary by a digest of it.

    ``digest`` is the salted truncated sha256 of the value; ``path`` is where
    the value was found (``"values.private_key"``) and is a DIAGNOSTIC only —
    it is deliberately NOT part of equality, because the same secret found at
    ``values.private_key`` in a tfstate and at ``values.private_key`` of a
    plan's prior state must compare equal even when the two readers spell the
    path differently.

    Equality is BY DIGEST. That is the whole point: the same secret from two
    sources still matches (no phantom drift) and two different secrets still
    differ (real drift on a sensitive field is still reportable, without
    printing either secret).

    :meth:`__bool__` RAISES, exactly as ``facts.Unresolved`` does, so a
    sensitive value cannot be truth-tested into a decision. A check that reads
    one abstains — which is precisely what a separate
    ``Unresolved("sensitive")`` marker would have bought, kept here without
    paying its cost of two incomparable secrets.
    """

    digest: str
    path: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.digest, str) or not re.fullmatch(
                r"[0-9a-f]{%d}" % DIGEST_LEN, self.digest):
            raise ValueError(
                f"Redacted.digest must be {DIGEST_LEN} lowercase hex characters "
                f"(build one with value_digest()), got {safe_repr(self.digest)}")

    # -- construction ---------------------------------------------------------

    @classmethod
    def of(cls, value: Any, path: str = "") -> "Redacted":
        """The digest of ``value``, stamped with where it was found."""
        return cls(value_digest(value), path)

    # -- comparison -----------------------------------------------------------

    def __eq__(self, other: Any) -> bool:
        # BY DIGEST, path excluded. Deliberately NOT equal to its own wire
        # string: a str cannot carry the same hash, and an object that compares
        # equal to something it hashes differently from is a set/dict bug
        # waiting to happen. The boundary is one-way anyway — before estate.py
        # a document holds objects, after it strings, never a mix.
        if isinstance(other, Redacted):
            return self.digest == other.digest
        return NotImplemented

    def __hash__(self) -> int:
        return hash(("redacted", self.digest))

    def __repr__(self) -> str:
        # The digest is safe to print — that is the entire premise — and the
        # path names an attribute, never a value.
        return f"Redacted(digest={self.digest!r}, path={self.path!r})"

    def __bool__(self) -> bool:
        raise TypeError(
            "Redacted is neither True nor False — this value was withheld at the "
            "loading boundary; compare digests with `==`, test for it with "
            "`redact.has_redacted(...)`, and emit an 'unverified' verdict, "
            "never 'ungrounded'"
        )

    # -- the wire form --------------------------------------------------------

    def wire(self) -> str:
        """The serialised spelling: ``redacted:sha256:<digest>``.

        ``Redacted`` has to cross two never-edit boundaries and cannot do it as
        an object: ``GcpSnapshot.from_dict`` is the strict path and
        ``fetch.write_snapshot`` is ``json.dumps``, which raises ``TypeError``
        on a frozen dataclass. ``estate.py`` converts every ``Redacted`` to
        this string in ONE pass immediately before ``from_dict`` (see
        :func:`to_wire`), and from there the snapshot, the sidecar and every
        rendered line hold the string.

        Two wire strings compare equal exactly when their digests do, so drift
        detection is unchanged across that boundary.

        **The one thing genuinely lost**, stated plainly: past the boundary the
        value is a plain ``str``, so truth-testing it no longer raises. That is
        unavoidable when the destination must be JSON. It is why
        :func:`has_redacted` MUST recognise BOTH the object and the wire
        string — that is what keeps the abstention path alive for anything
        reading the snapshot back off disk.
        """
        return WIRE_PREFIX + self.digest

    @classmethod
    def parse(cls, text: Any, path: str = "") -> "Redacted | None":
        """``Redacted`` if ``text`` is a wire string, else ``None``."""
        if not isinstance(text, str):
            return None
        match = _WIRE_RE.match(text)
        if match is None:
            return None
        return cls(match.group(1), path)


def is_wire(text: Any) -> bool:
    """True if ``text`` is the serialised spelling of a :class:`Redacted`."""
    return isinstance(text, str) and _WIRE_RE.match(text) is not None


# -- detection route 3: the name heuristic ------------------------------------

#: Substrings that make an attribute segment sensitive, matched CASE-FOLDED.
#:
#: **This list is DELIBERATELY OVER-BROAD and must not be trimmed.**
#: **Over-redacting costs an abstention; under-redacting costs a leak; those
#: are not comparable costs.** A future reviewer who wants a tighter list has
#: to argue with both of those sentences first, and has to say which leak they
#: are willing to own.
#:
#: Both spellings of every pattern are listed because a plan-JSON or an
#: HCL-JSON source spells attributes in camelCase as often as in snake_case;
#: :func:`is_sensitive_segment` case-folds anyway, and the squashed spellings
#: are what make ``privateKey`` and ``serviceAccountKey`` match.
SENSITIVE_PATTERNS = (
    "private_key", "privatekey",
    "secret", "client_secret", "clientsecret", "shared_secret", "sharedsecret",
    "password", "passwd", "passphrase", "pwd",
    "token",
    "credential", "credentials", "creds",
    "service_account_key", "serviceaccountkey",
    "cert", "certificate",
    "api_key", "apikey",
    "access_key", "accesskey",
    "encryption_key", "encryptionkey",
    "signing_key", "signingkey",
    "ssh_key", "sshkey",
    "authorization",
    "salt",
)

#: Segments that end with one of these are NEVER sensitive, matched
#: CASE-FOLDED.
#:
#: **This second list is not an optimisation and must not be dropped.** A KMS
#: key NAME, a crypto key id, a signing key URI, a key algorithm and a key
#: version are RESOURCE NAMES used as IDENTITY KEYS. Redacting one breaks
#: ``identity.canonical_key`` matching, which turns every such fact into a
#: sole-source fact — and a sole-source fact has nothing to disagree with, so
#: drift detection switches off for the whole category. Silently.
NEVER_SENSITIVE_SUFFIXES = (
    # the KMS family: names, ids, rings, versions and algorithms are addresses
    "key_name", "keyname",
    "key_id", "keyid",
    "key_uri", "keyuri",
    "key_ring", "keyring",
    "key_version", "keyversion",
    "key_algorithm", "keyalgorithm",
    "key_type", "keytype",
    "key_size", "keysize",
    "key_length", "keylength",
    # Secret Manager: the secret's NAME is an address, its payload is not
    "secret_id", "secretid",
    "secret_name", "secretname",
    "secret_version", "secretversion",
    # certificate resources: likewise addressed by name
    "cert_id", "certid",
    "cert_name", "certname",
    "certificate_id", "certificateid",
    "certificate_name", "certificatename",
    "certificate_authority", "certificateauthority",
)


def is_sensitive_segment(segment: Any) -> bool:
    """True if an attribute-path segment names a value that must be withheld.

    BOTH the segment and every pattern are CASE-FOLDED before comparing, and so
    is the never-sensitive check. Without the fold, a case-sensitive
    implementation passes every snake_case acceptance case and then leaks
    ``privateKey``, ``PrivateKey`` and ``serviceAccountKey`` out of any
    plan-JSON or HCL-JSON source, where camelCase is the normal spelling.

    The never-sensitive suffixes WIN over the patterns: ``kms_key_name``
    contains no pattern but ``crypto_key_version`` would match none either,
    while ``secret_id`` matches ``secret`` and must still survive.
    """
    if not isinstance(segment, str):
        return False                       # a list index names nothing
    folded = segment.casefold()
    for suffix in NEVER_SENSITIVE_SUFFIXES:
        if folded.endswith(suffix.casefold()):
            return False
    for pattern in SENSITIVE_PATTERNS:
        if pattern.casefold() in folded:
            return True
    return False


# -- walkers ------------------------------------------------------------------


def _is_sequence(value: Any) -> bool:
    """A JSON-ish array — a string is a scalar here, never a sequence."""
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _child(path: str, key: Any) -> str:
    return f"{path}.{key}" if path else str(key)


def _walk_redacted(value: Any, path: str, depth: int) -> Iterator[tuple[str, Any]]:
    # The marker test comes FIRST, before the depth cap, so a wire string that
    # to_wire() collapsed a too-deep subtree into is still surfaced.
    if isinstance(value, Redacted) or is_wire(value):
        yield path or "<root>", value
        return
    if depth >= MAX_DEPTH:
        return
    if isinstance(value, Mapping):
        for key, item in sorted(value.items(), key=lambda kv: str(kv[0])):
            yield from _walk_redacted(item, _child(path, key), depth + 1)
    elif _is_sequence(value):
        for index, item in enumerate(value):
            yield from _walk_redacted(item, f"{path}[{index}]", depth + 1)


def redacted_in(value: Any) -> Iterator[tuple[str, Any]]:
    """Yield ``(path, marker)`` for every withheld value in ``value``, where a
    marker is EITHER a :class:`Redacted` object OR its wire string.

    Both spellings are surfaced because they are the same fact on either side
    of the ``estate.py`` boundary: before it a reader holds the object, after
    it the snapshot holds the string, and a check that abstains on one must
    abstain on the other.
    """
    yield from _walk_redacted(value, "", 0)


def has_redacted(value: Any) -> bool:
    """True if ``value`` is or contains a withheld value, in EITHER spelling.

    This is the abstention hook: a check whose input answers True here cannot
    conclude anything about that input and must emit ``unverified``.
    """
    return next(redacted_in(value), None) is not None


def _to_wire(value: Any, path: str, depth: int) -> Any:
    if isinstance(value, Redacted):
        return value.wire()
    if depth >= MAX_DEPTH:
        # Fail SAFE at the cap: collapse the whole subtree to one wire string
        # rather than deep-copying a structure that may still hold objects
        # json.dumps cannot serialise.
        return Redacted.of(value, path or "<root>").wire()
    if isinstance(value, Mapping):
        return {key: _to_wire(item, _child(path, key), depth + 1)
                for key, item in value.items()}
    if _is_sequence(value):
        return [_to_wire(item, f"{path}[{index}]", depth + 1)
                for index, item in enumerate(value)]
    return copy.deepcopy(value)


def to_wire(document: Any) -> Any:
    """Deep copy of ``document`` with every :class:`Redacted` replaced by its
    :meth:`Redacted.wire` string.

    THE BOUNDARY IS THIS ONE FUNCTION, CALLED FROM ONE PLACE. ``estate.py``
    calls it in a single pass immediately before ``GcpSnapshot.from_dict``.
    Readers, mappers, ``merge`` and ``compare`` all carry the OBJECT, so
    digest comparison, the ``__bool__`` guard and the walkers work where the
    checks live; two conversion sites would be two places for the spelling to
    diverge, and diverged spellings compare unequal.
    """
    return _to_wire(document, "", 0)


# -- the one entry point ------------------------------------------------------


class RedactResult(NamedTuple):
    """What :func:`redact` returns: the new values and any notes it minted.

    ``notes`` is never dropped on the floor by a caller: a note here means a
    shape this module did not understand, and the fail-safe answer to that is
    over-redaction, which the reader has to be able to explain.
    """

    values: Any
    notes: tuple[str, ...]


def _collect(value: Any, vault: "SecretVault | None", depth: int = 0) -> None:
    """Feed every plaintext leaf under ``value`` to the vault."""
    if vault is None or depth >= MAX_DEPTH:
        return
    if isinstance(value, str):
        vault.add(value)
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _collect(item, vault, depth + 1)
    elif _is_sequence(value):
        for item in value:
            _collect(item, vault, depth + 1)


def _redacted(value: Any, path: str, vault: "SecretVault | None") -> Redacted:
    """Replace ``value`` wholesale, remembering its plaintext for the scrub.

    IDEMPOTENT, and that is load-bearing: the three routes run in sequence over
    the same document, so route 3 meets values route 1 already replaced.
    Digesting a :class:`Redacted` again would hash its REPR, and the same
    secret would then digest differently depending on which routes happened to
    fire — which is exactly the phantom drift the digest exists to prevent.
    """
    if isinstance(value, Redacted):
        return value
    _collect(value, vault)
    return Redacted.of(value, path or "<root>")


# -- detection route 1: the tfstate cty encoding ------------------------------


class _UnknownStep(Exception):
    """An instance's ``sensitive_attributes`` used a step shape this module
    does not decode. Raised internally so the FAIL-SAFE answer is one place."""

    def __init__(self, note: str) -> None:
        super().__init__(note)
        self.note = note


def _decode_step(step: Any) -> Any:
    """One cty path step → the mapping key or sequence index it selects.

    tfstate v4 spells a step as ``{"type": "get_attr", "value": "private_key"}``
    or ``{"type": "index", "value": {"number": 0}}``. Anything else raises, and
    the caller's answer to that is to redact the WHOLE instance.
    """
    if not isinstance(step, Mapping):
        raise _UnknownStep(f"sensitive-attribute step is {safe_repr(step)}, not an object")
    kind = step.get("type")
    if kind == "get_attr":
        name = step.get("value")
        if isinstance(name, str) and name:
            return name
        raise _UnknownStep("sensitive-attribute get_attr step carries no attribute name")
    if kind == "index":
        raw = step.get("value")
        if isinstance(raw, Mapping):
            for spelling in ("number", "string", "value"):
                if spelling in raw:
                    raw = raw[spelling]
                    break
            else:
                raise _UnknownStep("sensitive-attribute index step has no number/string key")
        if isinstance(raw, bool):
            raise _UnknownStep("sensitive-attribute index step is a boolean")
        if isinstance(raw, float) and raw.is_integer():
            return int(raw)
        if isinstance(raw, (int, str)):
            return raw
        raise _UnknownStep(f"sensitive-attribute index step is {safe_repr(raw)}")
    raise _UnknownStep(f"sensitive-attribute step type {kind!r} is not decoded by this reader")


def _apply_step_path(value: Any, steps: Sequence[Any], path: str,
                     vault: "SecretVault | None", notes: list[str],
                     spelling: str) -> Any:
    """Return ``value`` with the location named by ``steps`` replaced."""
    if not steps:
        return _redacted(value, path, vault)
    selector = _decode_step(steps[0])
    if isinstance(selector, str):
        if not isinstance(value, Mapping) or selector not in value:
            notes.append(f"sensitive attribute path {spelling} names no attribute here; "
                         f"nothing to redact")
            return value
        out = dict(value)
        out[selector] = _apply_step_path(value[selector], steps[1:],
                                         _child(path, selector), vault, notes, spelling)
        return out
    if not _is_sequence(value):
        notes.append(f"sensitive attribute path {spelling} indexes a non-list; "
                     f"nothing to redact")
        return value
    index = selector
    if not isinstance(index, int) or index < 0 or index >= len(value):
        notes.append(f"sensitive attribute path {spelling} indexes past the end; "
                     f"nothing to redact")
        return value
    out_list = list(value)
    out_list[index] = _apply_step_path(value[index], steps[1:],
                                       f"{path}[{index}]", vault, notes, spelling)
    return out_list


def _spell_path(steps: Any) -> str:
    """A path rendered for a NOTE — attribute names and indices only, never a
    value, so a note can be logged as-is."""
    if not _is_sequence(steps):
        return safe_repr(steps)
    out = []
    for step in steps:
        if isinstance(step, Mapping) and isinstance(step.get("value"), str):
            out.append(str(step["value"]))
        elif isinstance(step, Mapping):
            out.append(f"<{step.get('type')}>")
        else:
            out.append("<?>")
    return ".".join(out) or "<root>"


def redact_cty_paths(values: Any, sensitive_paths: Iterable[Any], *,
                     vault: "SecretVault | None" = None) -> RedactResult:
    """Route 1: decode the tfstate ``sensitive_attributes`` cty encoding — a
    list of step lists of ``get_attr`` and ``index`` objects — and replace
    exactly the values it names.

    **FAIL-SAFE**: an unrecognised step makes the WHOLE instance sensitive AND
    emits a note. A shape this reader does not understand never silently
    reveals a value; over-redaction is visible in the ledger, a leak is not.
    """
    notes: list[str] = []
    out = values
    for steps in sensitive_paths or ():
        spelling = _spell_path(steps)
        if not _is_sequence(steps):
            notes.append(f"unrecognised sensitive-attribute path {safe_repr(steps)}: "
                         f"not a list of steps — redacting the whole instance fail-safe")
            return RedactResult(_redacted(values, "<instance>", vault), tuple(notes))
        try:
            out = _apply_step_path(out, list(steps), "", vault, notes, spelling)
        except _UnknownStep as exc:
            notes.append(f"{exc.note} (at {spelling}) — redacting the whole instance "
                         f"fail-safe")
            return RedactResult(_redacted(values, "<instance>", vault), tuple(notes))
    return RedactResult(out, tuple(notes))


# -- detection route 2: the plan's sensitive mirror ---------------------------


def _apply_mirror(value: Any, mirror: Any, path: str,
                  vault: "SecretVault | None") -> Any:
    if mirror is True:
        # A `true` on a CONTAINER redacts the container WHOLE — the plan is
        # saying "everything under here is sensitive", and descending into it
        # to redact leaves would publish its shape and its non-secret siblings.
        return _redacted(value, path, vault)
    if isinstance(mirror, Mapping) and isinstance(value, Mapping):
        if not mirror:
            return value
        out = dict(value)
        for key, submirror in mirror.items():
            if key in out:
                out[key] = _apply_mirror(out[key], submirror, _child(path, key), vault)
        return out
    if _is_sequence(mirror) and _is_sequence(value):
        if not mirror:
            return value
        out_list = list(value)
        for index, submirror in enumerate(mirror):
            if index < len(out_list):
                out_list[index] = _apply_mirror(out_list[index], submirror,
                                                f"{path}[{index}]", vault)
        return out_list
    return value


def redact_mirror(values: Any, mirror: Any, *,
                  vault: "SecretVault | None" = None) -> Any:
    """Route 2: walk a plan's ``after_sensitive`` / ``before_sensitive``
    nested-true structure and replace what it marks.

    The mirror has the SHAPE of the values it describes, with ``true`` where a
    value is sensitive. A ``true`` on a CONTAINER redacts the container whole.
    """
    return _apply_mirror(values, mirror, "", vault)


# -- detection route 3 --------------------------------------------------------


def _apply_names(value: Any, path: str, depth: int,
                 vault: "SecretVault | None", notes: list[str]) -> Any:
    if depth >= MAX_DEPTH:
        notes.append(f"attribute {path or '<root>'} nests past MAX_DEPTH={MAX_DEPTH}; "
                     f"redacting it whole fail-safe")
        return _redacted(value, path, vault)
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            child = _child(path, key)
            if is_sensitive_segment(key):
                out[key] = _redacted(item, child, vault)
            else:
                out[key] = _apply_names(item, child, depth + 1, vault, notes)
        return out
    if _is_sequence(value):
        return [_apply_names(item, f"{path}[{index}]", depth + 1, vault, notes)
                for index, item in enumerate(value)]
    return value


def redact_by_name(values: Any, *, vault: "SecretVault | None" = None) -> RedactResult:
    """Route 3: apply :func:`is_sensitive_segment` to every mapping key at
    every depth, replacing the value under a sensitive key WHOLE.

    A value routes 1 or 2 already replaced comes back unchanged: replacement is
    idempotent, so the digest of a secret does not depend on which routes fired.
    """
    notes: list[str] = []
    return RedactResult(_apply_names(values, "", 0, vault, notes), tuple(notes))


def redact(values: Any, *, sensitive_paths: Iterable[Any] = (),
           mirror: Any = None,
           vault: "SecretVault | None" = None) -> RedactResult:
    """THE entry point. Three detection routes, applied IN THIS ORDER:

    1. ``sensitive_paths`` — the tfstate cty encoding (:func:`redact_cty_paths`),
       fail-safe on a step shape this reader does not decode;
    2. ``mirror`` — the plan's ``after_sensitive`` / ``before_sensitive``
       nested-true structure (:func:`redact_mirror`);
    3. the name heuristic (:func:`redact_by_name`), which is what catches an
       attribute the artifact never flagged — a ``terraform.tfstate`` stores
       sensitive values in PLAINTEXT and ``sensitive_attributes`` is a DISPLAY
       marker, so route 3 is not a backstop, it is the one that fires most.

    **Never mutates its input**: every container it touches is rebuilt, and a
    container it does not touch is shared with the input rather than copied.

    Pass ``vault`` to have every replaced plaintext remembered for the final
    scrub (:class:`SecretVault`); without one, attribute-level replacement is
    all you get and a value that reached a log line by another route survives.
    """
    notes: list[str] = []
    out = values
    if sensitive_paths:
        out, path_notes = redact_cty_paths(out, sensitive_paths, vault=vault)
        notes.extend(path_notes)
    if mirror is not None:
        out = redact_mirror(out, mirror, vault=vault)
    out, name_notes = redact_by_name(out, vault=vault)
    notes.extend(name_notes)
    return RedactResult(out, tuple(notes))


# -- the vault and the final scrub --------------------------------------------

#: Shortest plaintext the vault will remember. A three-character value would
#: match half the words in a report and scrub them; below this length a value
#: is not a secret worth the collateral damage.
MIN_SECRET_LEN = 8


class SecretVault:
    """The plaintexts seen at load time, kept for the FINAL scrub.

    Attribute-level replacement handles values a reader recognised. This
    handles everything else: a message a check built by hand, an interpolated
    fragment, a value logged before the reader reached it, an exception string
    carrying an attribute.

    Scrubbing runs LONGEST VALUE FIRST, so a secret that is a PREFIX of another
    cannot leave a tail behind — replace ``"abc"`` before ``"abcdef"`` and the
    text keeps ``"def"``, which is exactly the leak the vault exists to close.

    The vault holds PLAINTEXTS. It is process-local, is never serialised, and
    its ``repr`` is a count.
    """

    __slots__ = ("_replacements", "_ordered", "_min_len")

    def __init__(self, *, min_len: int = MIN_SECRET_LEN) -> None:
        self._replacements: dict[str, str] = {}
        self._ordered: tuple[tuple[str, str], ...] | None = ()
        self._min_len = max(1, int(min_len))

    def add(self, value: Any) -> bool:
        """Remember ``value`` if it is a plaintext worth scrubbing. Returns
        whether it was stored."""
        if not isinstance(value, str) or len(value) < self._min_len:
            return False
        if is_wire(value) or value in self._replacements:
            return False
        self._replacements[value] = WIRE_PREFIX + value_digest(value)
        self._ordered = None                    # invalidate the sorted view
        return True

    def add_all(self, values: Iterable[Any]) -> None:
        for value in values:
            self.add(value)

    def __len__(self) -> int:
        return len(self._replacements)

    def __bool__(self) -> bool:
        return bool(self._replacements)

    def __contains__(self, value: Any) -> bool:
        return isinstance(value, str) and value in self._replacements

    def __repr__(self) -> str:
        # NEVER the contents: a vault repr in a traceback would be the leak.
        return f"SecretVault(secrets={len(self._replacements)})"

    def _sorted(self) -> tuple[tuple[str, str], ...]:
        ordered = self._ordered
        if ordered is None:
            ordered = tuple(sorted(self._replacements.items(),
                                   key=lambda kv: (-len(kv[0]), kv[0])))
            self._ordered = ordered
        return ordered

    def scrub_text(self, text: Any) -> Any:
        """Replace every remembered plaintext with its wire string.

        Returns the INPUT OBJECT unchanged when nothing matched, so a no-op
        scrub over a whole report allocates nothing.
        """
        if not isinstance(text, str) or not self._replacements:
            return text
        out = text
        for secret, replacement in self._sorted():
            if secret in out:
                out = out.replace(secret, replacement)
        return out


def _scrub_value(vault: SecretVault, value: Any, depth: int = 0) -> Any:
    if isinstance(value, str):
        return vault.scrub_text(value)
    if depth >= MAX_DEPTH:
        return value
    if isinstance(value, Mapping):
        out = {}
        changed = False
        for key, item in value.items():
            new_key = vault.scrub_text(key)
            new_item = _scrub_value(vault, item, depth + 1)
            changed = changed or new_key is not key or new_item is not item
            out[new_key] = new_item
        return out if changed else value
    if isinstance(value, (list, tuple)):
        items = [_scrub_value(vault, item, depth + 1) for item in value]
        if all(new is old for new, old in zip(items, value)):
            return value
        return tuple(items) if isinstance(value, tuple) else items
    return value


def scrub_record(vault: SecretVault, record: Any) -> Any:
    """Scrub every string in a record, keys included, returning the INPUT
    OBJECT by identity when nothing matched."""
    if not vault:
        return record
    return _scrub_value(vault, record)


def scrub_verdict(vault: SecretVault, verdict: Any) -> Any:
    """Scrub a ``core.report.Verdict``'s target, message and suggestions.

    Returns the SAME verdict object when nothing matched — a verdict is frozen,
    so an unnecessary ``replace`` would allocate on every report.
    """
    if not vault or not dataclasses.is_dataclass(verdict):
        return verdict
    changes: dict[str, Any] = {}
    for name in ("target", "message"):
        old = getattr(verdict, name, None)
        if isinstance(old, str):
            new = vault.scrub_text(old)
            if new is not old:
                changes[name] = new
    old_suggestions = getattr(verdict, "suggestions", None)
    if isinstance(old_suggestions, (list, tuple)):
        new_suggestions = tuple(vault.scrub_text(s) for s in old_suggestions)
        if any(new is not old for new, old in zip(new_suggestions, old_suggestions)):
            changes["suggestions"] = new_suggestions
    if not changes:
        return verdict
    return dataclasses.replace(verdict, **changes)


def scrub_verdicts(vault: SecretVault, verdicts: Any) -> Any:
    """Scrub a sequence of verdicts, returning unchanged elements BY IDENTITY
    and the INPUT SEQUENCE ITSELF when nothing matched — a no-op scrub over a
    clean report allocates nothing, which is what makes it safe to run on
    EVERY report."""
    if not vault:
        return verdicts
    scrubbed = [scrub_verdict(vault, v) for v in verdicts]
    if all(new is old for new, old in zip(scrubbed, verdicts)):
        return verdicts
    return tuple(scrubbed) if isinstance(verdicts, tuple) else scrubbed


def scrub_report(vault: SecretVault, report: Any) -> Any:
    """Scrub a ``core.report.GroundingReport`` (or a ``report.PolicyReport``
    wrapping one) IN PLACE and return it.

    In place, deliberately: a caller that already holds the report object —
    the gate, the CLI's ``_finish_report``, the explain surface — must not be
    able to render the unscrubbed one by forgetting to use a return value.
    """
    if not vault or report is None:
        return report
    inner = getattr(report, "report", None)
    if inner is not None and hasattr(inner, "verdicts"):
        scrub_report(vault, inner)
        return report
    verdicts = getattr(report, "verdicts", None)
    if verdicts is None:
        return report
    scrubbed = scrub_verdicts(vault, verdicts)
    if scrubbed is not verdicts:
        report.verdicts = list(scrubbed)
    return report


# -- the log filter -----------------------------------------------------------

#: The root logger every module in this package logs under. Derived from the
#: name ``core.log.get_logger`` handed back rather than hardcoded, because
#: ``core/log.py`` is vendored and never edited — asking it is the only way to
#: stay in step with it.
_HARNESS_ROOT = logger.name.split(".", 1)[0]


class SecretScrubFilter(logging.Filter):
    """A ``logging.Filter`` that rewrites a record's message and arguments
    through a :class:`SecretVault`. It never drops a record and never raises:
    a filter that raised would take all logging down with it.
    """

    def __init__(self, vault: SecretVault) -> None:
        super().__init__()
        self.vault = vault

    def _scrub_args(self, args: Any) -> Any:
        if isinstance(args, Mapping):
            out = {k: self._scrub_one(v) for k, v in args.items()}
            return out if any(out[k] is not args[k] for k in args) else args
        if isinstance(args, tuple):
            out_t = tuple(self._scrub_one(a) for a in args)
            return out_t if any(n is not o for n, o in zip(out_t, args)) else args
        return self._scrub_one(args)

    def _scrub_one(self, arg: Any) -> Any:
        vault = self.vault
        if isinstance(arg, str):
            return vault.scrub_text(arg)
        # A non-string argument is stringified by %-formatting, so its str()
        # is what reaches the stream. Replace it with the scrubbed TEXT only
        # when the scrub actually changed something — swapping an int for a
        # str would break a "%d" and a leak is the only thing worth that.
        try:
            text = str(arg)
        except Exception:                     # noqa: BLE001 - a broken __str__
            return arg
        scrubbed = vault.scrub_text(text)
        return scrubbed if scrubbed is not text else arg

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            if not self.vault:
                return True                   # nothing collected: no work, no allocation
            msg = record.msg
            if isinstance(msg, str):
                scrubbed = self.vault.scrub_text(msg)
                if scrubbed is not msg:
                    record.msg = scrubbed
            if record.args:
                args = self._scrub_args(record.args)
                if args is not record.args:
                    record.args = args
            exc_text = getattr(record, "exc_text", None)
            if isinstance(exc_text, str):
                scrubbed_exc = self.vault.scrub_text(exc_text)
                if scrubbed_exc is not exc_text:
                    record.exc_text = scrubbed_exc
        except Exception:                     # noqa: BLE001 - logging must never break
            pass
        return True


class _NullHandler(logging.Handler):
    """Emits nothing. It exists ONLY to carry the filter when the ``harness``
    logger has no handler yet, so the boundary is in place before
    ``core.log.setup_logging`` runs."""

    def emit(self, record: logging.LogRecord) -> None:
        pass


_INSTALLED: SecretScrubFilter | None = None
_OWNED_HANDLER: logging.Handler | None = None


def install_log_filter(vault: SecretVault) -> SecretScrubFilter:
    """Attach a :class:`SecretScrubFilter` to the HANDLERS of the ``harness``
    logger — NOT to the logger itself.

    **Why the handlers.** A ``logging.Filter`` on a logger only sees records
    that THAT logger created. Every module in this package logs through a
    ``harness.*`` CHILD logger obtained from ``core.log.get_logger(__name__)``,
    and a child's records propagate to the parent's HANDLERS without ever
    passing the parent's own filters. Attaching to the logger therefore passes
    a naive test written against the bare ``harness`` name and leaks every
    real record.

    When the logger has no handler yet, one level-``NOTSET`` no-op handler
    carrying the filter is installed, so the boundary exists before
    ``setup_logging`` runs. Idempotent: the handler set is re-scanned on every
    call. ``core/log.py`` is never edited.
    """
    global _INSTALLED, _OWNED_HANDLER
    root = logging.getLogger(_HARNESS_ROOT)
    if _INSTALLED is not None and _INSTALLED.vault is not vault:
        remove_log_filter()
    filt = _INSTALLED
    if filt is None:
        filt = SecretScrubFilter(vault)
        _INSTALLED = filt
    if not root.handlers:
        if _OWNED_HANDLER is None:
            handler = _NullHandler()
            handler.setLevel(logging.NOTSET)
            _OWNED_HANDLER = handler
        root.addHandler(_OWNED_HANDLER)
    for handler in root.handlers:
        if filt not in handler.filters:
            handler.addFilter(filt)
    # Deliberately SILENT. An installer that logs emits a record through the
    # very handlers it is wiring, which makes the boundary's own behaviour
    # depend on the order the wiring happened in; and this module may never log
    # a value, not even one of its own.
    return filt


def ensure_log_filter(vault: SecretVault) -> SecretScrubFilter:
    """Cheap idempotent re-scan-and-re-attach. Call at EVERY report and render
    boundary — the gate check, the CLI's ``_finish_report``, the explain
    surface — in addition to the single install in ``sources.py``.

    **Why one install is not enough.** ``core.log.setup_logging`` is
    idempotent-but-RECONFIGURING: it REMOVES and RE-ADDS its own owned
    handlers. Any ``setup_logging`` call after the install — a CLI that
    configures logging lazily, a second gate construction, a test that raises
    verbosity — produces handlers carrying no filter, and the vault's canaries
    flow straight through them.

    The no-change path allocates nothing: it walks the live handler list and
    tests membership, and returns.
    """
    filt = _INSTALLED
    if filt is None or filt.vault is not vault:
        return install_log_filter(vault)
    root = logging.getLogger(_HARNESS_ROOT)
    if not root.handlers:
        return install_log_filter(vault)
    for handler in root.handlers:
        if filt not in handler.filters:
            handler.addFilter(filt)
    return filt


def remove_log_filter() -> None:
    """Restore the handler set EXACTLY: drop the filter from every handler
    carrying it, and remove the no-op handler this module added."""
    global _INSTALLED, _OWNED_HANDLER
    root = logging.getLogger(_HARNESS_ROOT)
    filt = _INSTALLED
    if filt is not None:
        for handler in list(root.handlers):
            if filt in handler.filters:
                handler.removeFilter(filt)
    if _OWNED_HANDLER is not None and _OWNED_HANDLER in root.handlers:
        root.removeHandler(_OWNED_HANDLER)
    _INSTALLED = None
    _OWNED_HANDLER = None
