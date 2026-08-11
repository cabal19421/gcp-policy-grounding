"""The captured terraform provider schema: loading, settings, and freshness.

The gate judges terraform proposals against the provider that will actuate
them — but it NEVER shells out and never touches the network, so this module
is CONSUMPTION-ONLY. The operator captures the schema themselves, locally and
credential-free, in a checkout where ``terraform init`` has already run::

    terraform providers schema -json > provider-schema.json

and the gate reads that file. Nothing here invokes terraform, ever.

TWO ACCEPTED SHAPES, AND THE VERSION-HONESTY RULE
-------------------------------------------------
The raw ``terraform providers schema -json`` output does NOT carry the
provider VERSION — it is keyed by provider ADDRESS
(``registry.terraform.io/hashicorp/google``) with ``resource_schemas`` per
address, and nothing in it says which release produced it. So:

- the RAW shape is accepted as-is, tolerantly (unrecognized keys inside it are
  terraform's business, not ours), and the version is recorded as UNKNOWN —
  messages say "the captured schema" and never invent a version string;
  freshness then keys on the FILE's own modification time;
- the optional WRAPPER shape — :data:`WRAPPER_SCHEMA`, produced by one
  documented ``python``/``jq`` line around the same command — records what the
  operator truly knows: a ``captured_at`` instant and, optionally, the
  provider versions ``.terraform.lock.hcl`` pins. The wrapper's OWN keys are
  parsed STRICTLY (an unrecognized key is refused by name, exactly as
  :func:`gcp_grounding.discovery.parse_config` refuses one), because a typo'd
  ``captured_at`` silently dropped is a freshness check silently disarmed.

A version is only ever printed where one was truly recorded. There is no
default, no guess, and no "latest".

THE SETTINGS, IN THE STANDARD THREE LAYERS
------------------------------------------
``--provider-schema PATH`` (repeatable — one file per provider, so ``google``
and ``google-beta`` can each contribute), :data:`PROVIDER_SCHEMA_ENV`
(``os.pathsep``-separated), and the ``provider_schema`` key of
``.gcp-grounding.json``. The strictness knob is ``--schema-policy`` /
:data:`SCHEMA_POLICY_ENV` / the ``schema_policy`` config key, one of
:data:`SCHEMA_POLICIES`. Both ride on
:class:`gcp_grounding.sources.SourceOptions`, so
``discovery.resolve_settings`` layers them exactly like every other setting
and ``--state-explain`` reports which layer supplied each.

HOW A CHECK LEARNS THE ANSWER — :func:`runtime_for`. A CLI-bearing caller
resolves the four layers once and :func:`activate`\\ s the result for the run
(``cli._ground`` does this); a caller that never resolved settings — a direct
:func:`gcp_grounding.preflight.ground_policy` call, the changed-file gate —
falls back to the AMBIENT layers, environment over the config file discovered
by walking up from the proposal, which are the same two layers every other
setting honours when no flag was typed. The fallback never raises.

FRESHNESS: A DEDICATED STALENESS NOTE, NOT A SourceLedger CATEGORY
------------------------------------------------------------------
A stale schema must demote to loud abstention like any other stale source, and
it does — but through a dedicated note computed here, not through the
:class:`gcp_grounding.provenance.SourceLedger`. The ledger's categories are
the ESTATE domains (``firewall_rules``, ``iam_bindings``, …): a provider
schema is not a current-state table, it is a vocabulary about the PROVIDER,
and wiring a new pseudo-category through merge/estate/facts would both be
invasive and make the schema appear in coverage tables that answer a
different question ("what does the estate view enumerate?"). The dedicated
note keeps the same behaviour — past :data:`gcp_grounding.freshness
.MAX_AGE_DEFAULT` (or the configured ``--max-age``), every finding the checks
would have made is demoted to ``unverified`` naming the age and the recapture
command — at none of that cost. The clock is
:func:`gcp_grounding.freshness.resolve_now`, the same one every other age
answers against.

The staleness stamp is the wrapper's ``captured_at`` when one was recorded,
else the file's own modification time — stated as such, never presented as a
capture time somebody attested to.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from . import freshness
from .core.log import get_logger

logger = get_logger(__name__)

__all__ = [
    "WRAPPER_SCHEMA",
    "PROVIDER_SCHEMA_ENV",
    "SCHEMA_POLICY_ENV",
    "SCHEMA_POLICIES",
    "DEFAULT_SCHEMA_POLICY",
    "CAPTURE_COMMAND",
    "RAW_MARKER",
    "ProviderSchema",
    "Runtime",
    "load",
    "load_cached",
    "reset_cache",
    "activate",
    "active",
    "runtime_from_settings",
    "runtime_for",
    "staleness",
]

#: The one wrapper schema id this module reads. The raw
#: ``terraform providers schema -json`` shape needs no id: it is recognized by
#: :data:`RAW_MARKER`.
WRAPPER_SCHEMA = "gcp-provider-schema/1"

#: Captured provider schema path(s), ``os.pathsep``-separated — the environment
#: spelling of ``--provider-schema``.
PROVIDER_SCHEMA_ENV = "GCP_GROUNDING_PROVIDER_SCHEMA"

#: The environment spelling of ``--schema-policy``.
SCHEMA_POLICY_ENV = "GCP_GROUNDING_SCHEMA_POLICY"

#: What a provider-schema finding costs. ``block`` keeps the honest statuses
#: (``ungrounded``/``contradicted`` fail the gate — which is exactly what
#: ``terraform plan`` would do to the same attribute, so blocking at write time
#: matches actuation reality); ``annotate`` demotes findings to ``unverified``
#: warnings for hook-side gentleness; ``off`` ignores the captured schema.
SCHEMA_POLICIES = ("block", "annotate", "off")

#: The default is ``block``, deliberately: an unknown attribute is not a
#: judgment call — the provider that actuates the change will refuse it at plan
#: time, so the gate refusing it at write time blocks nothing that could ever
#: have applied. ``annotate`` exists for the hook-annotates-while-CI-blocks
#: pattern, not as the default.
DEFAULT_SCHEMA_POLICY = "block"

#: THE capture command, spelled once so every message and every document quotes
#: the same line. Local, credential-free, and run by the OPERATOR — the gate
#: never invokes terraform.
CAPTURE_COMMAND = "terraform providers schema -json > provider-schema.json"

#: The top-level key that marks the raw ``terraform providers schema -json``
#: shape.
RAW_MARKER = "provider_schemas"

#: The wrapper's own keys — parsed strictly; see the module docstring.
_WRAPPER_KEYS = ("schema", "captured_at", "provider_versions", "raw")

#: Keys of one raw resource entry that make a bare block acceptable where a
#: ``{"version": n, "block": {...}}`` envelope was expected — tolerance for the
#: raw shape, never applied to the wrapper's own keys.
_BLOCK_KEYS = ("attributes", "block_types")


# -- what a loaded schema is ---------------------------------------------------


@dataclass(frozen=True)
class ProviderSchema:
    """One captured provider schema file, loaded and indexed.

    ``resources`` maps a resource TYPE to ``{provider address: block}``, so a
    type two providers both define (``google`` and ``google-beta``) keeps both
    definitions and a check can consult their union — the gate cannot always
    know which provider actuates a block, and the union is the conservative
    reading (a finding only when NO supplied provider knows the name).

    ``provider_versions`` is EMPTY unless the wrapper recorded versions; an
    empty map means UNKNOWN and is rendered as nothing, never as a guess.
    ``stamp`` is the freshness instant and ``stamp_source`` says whether it is
    the wrapper's ``captured_at`` or the file's modification time.
    """

    path: str
    resources: Mapping[str, Mapping[str, Mapping[str, Any]]]
    providers: tuple[str, ...] = ()
    provider_versions: Mapping[str, str] = None  # type: ignore[assignment]
    captured_at: str = ""
    stamp: datetime | None = None
    stamp_source: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "resources", dict(self.resources))
        object.__setattr__(self, "provider_versions",
                           dict(self.provider_versions or {}))

    def blocks_for(self, resource_type: str) -> "dict[str, Mapping[str, Any]]":
        """``{provider address: block}`` for *resource_type* — empty when the
        captured schema does not define it."""
        return dict(self.resources.get(resource_type, {}))

    def resource_types(self) -> tuple[str, ...]:
        return tuple(sorted(self.resources))

    def version_label(self) -> str:
        """The recorded provider versions, or ``""`` when none was recorded.

        Rendered as ``google 6.8.0`` (short provider name), one clause per
        recorded provider. NOTHING is rendered for a raw capture: the raw
        output carries no version, and this label never invents one.
        """
        if not self.provider_versions:
            return ""
        return ", ".join(f"{address.rsplit('/', 1)[-1]} {version}"
                         for address, version
                         in sorted(self.provider_versions.items()))


# -- loading -------------------------------------------------------------------


def load(path: str | os.PathLike[str]) -> tuple[ProviderSchema | None,
                                                tuple[str, ...]]:
    """One captured schema from disk, or ``None`` plus every problem found.

    Never raises. Strict about the WRAPPER's own keys, tolerant of the raw
    terraform shape — see the module docstring for why the asymmetry is the
    honest one.
    """
    fspath = os.path.abspath(os.fspath(path))
    try:
        with open(fspath, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        return None, (f"the provider schema at {fspath} could not be read "
                      f"({type(exc).__name__}: {exc})",)
    return _parse(data, path=fspath)


def _parse(data: Any, *, path: str) -> tuple[ProviderSchema | None,
                                             tuple[str, ...]]:
    if not isinstance(data, Mapping):
        return None, (f"{path}: a provider schema must be a JSON object, got "
                      f"{type(data).__name__}",)

    captured_at = ""
    versions: dict[str, str] = {}
    problems: list[str] = []

    if data.get("schema") == WRAPPER_SCHEMA:
        raw, captured_at, versions, problems = _parse_wrapper(data, path)
        if problems:
            return None, tuple(problems)
    elif "schema" in data and RAW_MARKER not in data:
        return None, (f"{path}: 'schema' is {data.get('schema')!r} — expected "
                      f"{WRAPPER_SCHEMA!r}, or the raw 'terraform providers "
                      f"schema -json' output (which carries "
                      f"'{RAW_MARKER}' and no 'schema' key)",)
    elif RAW_MARKER in data:
        raw = data
    else:
        return None, (f"{path}: neither the raw 'terraform providers schema "
                      f"-json' shape (no '{RAW_MARKER}' key) nor a "
                      f"{WRAPPER_SCHEMA!r} wrapper — capture one with: "
                      f"{CAPTURE_COMMAND}",)

    schemas = raw.get(RAW_MARKER)
    if not isinstance(schemas, Mapping):
        return None, (f"{path}: '{RAW_MARKER}' must be an object keyed by "
                      f"provider address, got "
                      f"{type(schemas).__name__}",)

    resources: dict[str, dict[str, Mapping[str, Any]]] = {}
    providers: list[str] = []
    for address in sorted(map(str, schemas)):
        entry = schemas[address]
        if not isinstance(entry, Mapping):
            logger.debug("%s: provider %s is not an object — skipped", path,
                         address)
            continue
        providers.append(address)
        tables = entry.get("resource_schemas")
        if not isinstance(tables, Mapping):
            continue
        for rtype in sorted(map(str, tables)):
            block = _resource_block(tables[rtype])
            if block is None:
                logger.debug("%s: %s.%s carries no readable block — skipped",
                             path, address, rtype)
                continue
            resources.setdefault(rtype, {})[address] = block

    if not resources:
        return None, (f"{path}: the captured schema defines no resource type "
                      f"at all (no provider address carries a non-empty "
                      f"'resource_schemas') — there is nothing to judge a "
                      f"terraform proposal against; recapture with: "
                      f"{CAPTURE_COMMAND}",)

    stamp, source = _stamp(captured_at, path)
    return ProviderSchema(path=path, resources=resources,
                          providers=tuple(providers),
                          provider_versions=versions,
                          captured_at=captured_at, stamp=stamp,
                          stamp_source=source), ()


def _parse_wrapper(data: Mapping[str, Any], path: str
                   ) -> tuple[Any, str, dict[str, str], list[str]]:
    """The strict wrapper parse: ``(raw, captured_at, versions, problems)``."""
    problems: list[str] = []
    unrecognized = sorted(set(map(str, data)) - set(_WRAPPER_KEYS))
    if unrecognized:
        problems.append(f"{path}: unrecognized wrapper key(s) {unrecognized} - "
                        f"a typo must not silently disarm the freshness or "
                        f"version record; expected only "
                        f"{sorted(_WRAPPER_KEYS)}")

    captured_at = ""
    raw_stamp = data.get("captured_at")
    if raw_stamp is not None:
        if freshness.parse_timestamp(raw_stamp) is None:
            problems.append(f"{path}: 'captured_at' {raw_stamp!r} is not an "
                            f"AWARE ISO-8601 instant — a naive or unparseable "
                            f"stamp is refused rather than assumed, because "
                            f"assuming shifts every age answer")
        else:
            captured_at = str(raw_stamp).strip()

    versions: dict[str, str] = {}
    raw_versions = data.get("provider_versions")
    if raw_versions is not None:
        if not isinstance(raw_versions, Mapping) or any(
                not isinstance(k, str) or not isinstance(v, str) or not v
                for k, v in raw_versions.items()):
            problems.append(f"{path}: 'provider_versions' must map provider "
                            f"addresses to non-empty version strings")
        else:
            versions = dict(raw_versions)

    raw = data.get("raw")
    if not isinstance(raw, Mapping) or RAW_MARKER not in raw:
        problems.append(f"{path}: 'raw' must hold the unmodified 'terraform "
                        f"providers schema -json' output (an object carrying "
                        f"'{RAW_MARKER}')")
        raw = {}
    return raw, captured_at, versions, problems


def _resource_block(entry: Any) -> Mapping[str, Any] | None:
    """The ``block`` of one raw resource entry, tolerantly.

    The documented shape is ``{"version": n, "block": {...}}``; a bare block
    (carrying ``attributes``/``block_types`` directly) is accepted too, because
    the raw side is terraform's format to evolve, not ours to refuse.
    """
    if not isinstance(entry, Mapping):
        return None
    block = entry.get("block")
    if isinstance(block, Mapping):
        return block
    if any(key in entry for key in _BLOCK_KEYS):
        return entry
    return None


def _stamp(captured_at: str, path: str) -> tuple[datetime | None, str]:
    """The freshness instant and its source: the wrapper's ``captured_at``
    where one was recorded, else the file's own modification time."""
    if captured_at:
        parsed = freshness.parse_timestamp(captured_at)
        if parsed is not None:
            return parsed, "captured_at"
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        logger.debug("the mtime of %s could not be read — no freshness stamp",
                     path)
        return None, ""
    return datetime.fromtimestamp(mtime, tz=timezone.utc), "file mtime"


# -- the load cache ------------------------------------------------------------

#: path → ((mtime, size), (schema, problems)). Keyed on the file's own identity
#: so an edited or recaptured schema re-loads without any reset call.
_CACHE: dict[str, tuple[tuple[float, int], tuple[ProviderSchema | None,
                                                 tuple[str, ...]]]] = {}


def load_cached(path: str | os.PathLike[str]) -> tuple[ProviderSchema | None,
                                                       tuple[str, ...]]:
    """:func:`load`, cached by the file's mtime and size. Never raises."""
    fspath = os.path.abspath(os.fspath(path))
    try:
        stat = os.stat(fspath)
        signature = (stat.st_mtime, stat.st_size)
    except OSError:
        _CACHE.pop(fspath, None)
        return load(fspath)
    cached = _CACHE.get(fspath)
    if cached is not None and cached[0] == signature:
        return cached[1]
    result = load(fspath)
    _CACHE[fspath] = (signature, result)
    return result


def reset_cache() -> None:
    """Drop the load cache (and any active runtime) — for tests."""
    global _ACTIVE
    _CACHE.clear()
    _ACTIVE = None


# -- the per-run configuration -------------------------------------------------


@dataclass(frozen=True)
class Runtime:
    """The provider-schema configuration one grounding run judges under.

    ``policy`` is ``None`` when NOBODY chose — distinct from an explicit value,
    because "a policy was configured but no schema was supplied" is the one
    situation that earns the loud no-schema abstention, and it cannot be told
    apart from silence if the default is applied early. ``max_age`` and
    ``now`` stay in their RAW spellings; they are parsed where they are used,
    fail-open.
    """

    paths: tuple[str, ...] = ()
    policy: str | None = None
    max_age: str | None = None
    now: str | None = None
    origin: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "paths", tuple(self.paths))

    @property
    def configured(self) -> bool:
        """Whether anything at all was configured. False is off-by-absence:
        the checks stay byte-silent, exactly as unconfigured requirements
        do."""
        return bool(self.paths or self.policy)

    @property
    def effective_policy(self) -> str:
        return self.policy or DEFAULT_SCHEMA_POLICY


#: The runtime a CLI-bearing boundary resolved for the current run, or ``None``
#: when no boundary did — in which case :func:`runtime_for` resolves the
#: ambient layers itself.
_ACTIVE: Runtime | None = None


def activate(runtime: Runtime | None) -> Runtime | None:
    """Install *runtime* as the run's resolved answer; returns the previous one
    so a caller can restore it in a ``finally``."""
    global _ACTIVE
    previous = _ACTIVE
    _ACTIVE = runtime
    return previous


def active() -> Runtime | None:
    return _ACTIVE


def runtime_from_settings(settings: Any) -> Runtime:
    """The runtime a resolved :class:`gcp_grounding.discovery.Settings` names —
    what ``cli._ground`` activates, carrying the full four-layer answer."""
    options = getattr(settings, "options", settings)
    return Runtime(paths=tuple(getattr(options, "provider_schema", ()) or ()),
                   policy=getattr(options, "schema_policy", None),
                   max_age=getattr(options, "max_age", None),
                   now=getattr(options, "now", None),
                   origin="settings")


def runtime_for(source: str) -> Runtime:
    """The runtime governing a grounding of *source*.

    The ACTIVE runtime wins when a CLI-bearing boundary installed one — it is
    the full flags-over-env-over-config answer, already resolved. Otherwise
    the AMBIENT layers are read here: the environment, then the config file
    discovered by walking up from *source* — the same two layers every other
    setting honours when no flag was typed. NEVER RAISES: a broken config or
    an unwalkable path resolves to the environment alone.
    """
    if _ACTIVE is not None:
        return _ACTIVE
    paths = _split(os.environ.get(PROVIDER_SCHEMA_ENV, ""))
    policy = (os.environ.get(SCHEMA_POLICY_ENV) or "").strip() or None
    max_age = os.environ.get("GCP_GROUNDING_MAX_AGE")
    if not paths or policy is None or max_age is None:
        config = _discovered_config(source)
        if config is not None:
            paths = paths or tuple(config.get("provider_schema", ()) or ())
            policy = policy or config.get("schema_policy") or None
            if max_age is None:
                max_age = config.get("max_age")
    return Runtime(paths=paths, policy=policy, max_age=max_age,
                   origin="env/config")


def _split(raw: str) -> tuple[str, ...]:
    return tuple(part for part in raw.split(os.pathsep) if part)


def _discovered_config(source: str) -> Any:
    """The config governing *source*, or ``None`` — resolved through the ONE
    discovery walk, lazily, so a checkout without the discovery module keeps
    the environment layer it had."""
    try:
        from . import discovery
    except ImportError:
        logger.debug("gcp_grounding.discovery is not part of this checkout — "
                     "the provider-schema config layer is unavailable")
        return None
    try:
        config, problems = discovery.discover(source or ".")
    except Exception:                       # noqa: BLE001 — never raise upward
        logger.debug("provider-schema config discovery from %r raised", source,
                     exc_info=True)
        return None
    if problems:
        logger.debug("provider-schema config discovery from %r: %s", source,
                     "; ".join(problems))
    return config


# -- freshness ----------------------------------------------------------------


def staleness(schema: ProviderSchema, runtime: Runtime) -> str:
    """Why *schema* is too old to block on, or ``""`` while it is fresh.

    The ceiling is the run's ``--max-age`` (``off`` disables it), defaulting
    to :data:`gcp_grounding.freshness.MAX_AGE_DEFAULT`; the clock is
    :func:`gcp_grounding.freshness.resolve_now`. A schema with no stamp at all
    (no wrapper ``captured_at`` and an unreadable mtime) is not called stale —
    there is no age to compare — and an unparseable ceiling or clock skips the
    evaluation at debug rather than crashing a check. The returned sentence
    names the age, the ceiling, the stamp's provenance and the recapture
    command, so the abstention it feeds is actionable on its own.
    """
    if schema.stamp is None:
        return ""
    try:
        max_age = (freshness.parse_duration(runtime.max_age)
                   if runtime.max_age is not None
                   else freshness.MAX_AGE_DEFAULT)
    except ValueError:
        logger.debug("provider-schema staleness skipped: max_age %r is not a "
                     "duration", runtime.max_age)
        return ""
    if max_age is None:                     # 'off': no ceiling, nothing stale
        return ""
    try:
        now = freshness.resolve_now(runtime.now)
    except ValueError:
        logger.debug("provider-schema staleness skipped: the clock %r could "
                     "not be resolved", runtime.now)
        return ""
    age = now - schema.stamp
    if age <= max_age:
        return ""
    return (f"the captured provider schema at {schema.path} is "
            f"{freshness._describe(age)} old "
            f"({schema.stamp_source} {schema.stamp.isoformat()}), past the "
            f"{freshness._describe(max_age)} ceiling — the provider it "
            f"describes may no longer be the one that actuates this change, "
            f"so its findings are demoted to abstentions; recapture it where "
            f"terraform init has run: {CAPTURE_COMMAND}")
