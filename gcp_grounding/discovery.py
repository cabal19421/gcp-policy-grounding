"""Find the config file, parse it, and say WHERE EVERY SETTING CAME FROM.

A guardrail nobody can configure is a guardrail nobody runs. This module makes
the common case zero-flag: drop a :data:`CONFIG_NAMES` file next to your
terraform and the hook finds it, PER EDITED FILE, by walking up from that file.
An agent editing three modules in one repo therefore gets three different,
correct current-state views, which is something a hook command line — one fixed
string nobody edits per run — structurally cannot express.

IT FINDS AND PARSES SETTINGS AND NOTHING ELSE. It hands a
:class:`~gcp_grounding.sources.SourceOptions` to
:func:`gcp_grounding.sources.load_current` and assembles no current state
itself, because there is exactly one assembler and it is not this module.

THE CONFIG FILE
---------------
The document is STRICTLY parsed: an unrecognized top-level key AND an
unrecognized key inside the ``terraform`` object are both refused, naming the
key. That mirrors :meth:`gcp_grounding.knowledge.GcpSnapshot.from_dict`, and for
the same reason — a typo must not silently demote a setting. ``snapshto`` read
as "nothing configured" is a run that grounds against no state at all and says
so nowhere.

EVERY RELATIVE PATH RESOLVES AGAINST THE CONFIG FILE'S DIRECTORY, never against
the current working directory: the config travels with the repo, and a hook is
invoked with whatever working directory the agent's shell happened to be in.
The ``targets`` keys are proposal paths relative to that same directory.

A CONFIG THAT FAILS TO PARSE YIELDS ``None`` PLUS THE PROBLEMS, NEVER A PARTIAL
CONFIG — including when the only bad key is one ``targets`` entry. Half a config
is a setting silently missing, which is the failure the strict parse exists to
prevent, arriving one layer down.

AUTO-DETECTION, AND THE ONE FILE IT REFUSES
-------------------------------------------
So the very first run still works, the same walk takes a sibling
``terraform.tfstate`` when there is one. It DELIBERATELY REFUSES the copy under
a ``.terraform`` directory: with a ``gcs`` or ``s3`` backend that file holds only
the backend configuration ``terraform init`` recorded and carries no
``resources`` array at all — which is byte-indistinguishable from a clean, empty
estate. Reading it would produce a confident "there are no firewall rules" from
a file that never described any. When it is the only candidate the answer is NO
SOURCE plus :func:`remote_backend_problem`, which names the situation and tells
the operator to run ``terraform state pull``.

Auto-detection NEVER picks up a terraform DIRECTORY and never a PLAN. Those
require an explicit flag or a config entry, because scanning a tree for HCL is
exactly where a wrong guess becomes an authoritative-looking baseline.

SETTINGS PRECEDENCE, TRACKED PER FIELD
--------------------------------------
:class:`Settings` WRAPS a ``SourceOptions`` and does not restate its fields.
There is one definition of what a source option is, so
:func:`to_source_options` is a FIELD ACCESS plus the injected clock rather than
a field-by-field re-mapping — which is a place to silently lose a field — and
there is one env resolver, :func:`gcp_grounding.sources.from_env`, rather than a
second one that can silently apply a different precedence. ``targets`` and
``requirements`` are the only two genuinely settings-only fields; they have no
place in a source options object and so they live here.

:func:`resolve_settings` applies cli over env over config-file over
auto-detected over defaults and records in :attr:`Settings.origins` which layer
supplied each field, TOTAL over :data:`SETTINGS_FIELDS`. That map is what the
explain surface prints: a user surprised by a verdict must be able to see where
the tool got each of its inputs.

:func:`to_source_options` IS THE ONLY WAY A CLI-BEARING CALLER BUILDS OPTIONS.
``sources.from_env`` resolves env and explicit overrides only and knows nothing
about a config file or auto-detection, so a caller that uses it on a path which
also promises discovery silently ignores whatever the user wrote in the config
file — the run succeeds, it just used the wrong state.

THE CLOCK is :func:`gcp_grounding.freshness.resolve_now` and this module does
not define a second one. The gate and the CLI resolve it ONCE per run at their
own boundary and inject the result into ``to_source_options``.
"""

from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from . import drift, freshness, merge, provenance, provider_schema, sources
from .baseline import TargetRef
from .core.log import get_logger
from .sources import SourceOptions

logger = get_logger(__name__)

__all__ = [
    "CONFIG_NAMES",
    "CONFIG_ENV",
    "CONFIG_SCHEMA",
    "MAX_WALK_UP",
    "REPO_MARKER",
    "STATE_NAME",
    "BACKEND_DIR",
    "TARGET_HOW",
    "REQUIREMENTS_ENV",
    "CONFIG_KEYS",
    "TERRAFORM_KEYS",
    "OPTION_FIELDS",
    "SETTINGS_FIELDS",
    "ORIGIN_LABELS",
    "Config",
    "Auto",
    "Settings",
    "remote_backend_problem",
    "walk_up",
    "parse_config",
    "load_config",
    "discover",
    "auto_detect",
    "resolve_settings",
    "to_source_options",
    "settings_for",
]

# -- the file, and where it is looked for -------------------------------------

#: THE config file name. One element, dot-prefixed: a second accepted spelling
#: is a second file an operator can edit while the tool reads the other one.
CONFIG_NAMES = (".gcp-grounding.json",)

#: The environment override. It SHORT-CIRCUITS the walk entirely, so a CI job
#: can name one config for a checkout whose layout it does not control.
CONFIG_ENV = "GCP_GROUNDING_CONFIG"

#: The one schema string this module reads.
CONFIG_SCHEMA = "gcp-grounding-config/1"

#: How many levels the walk climbs. A bound rather than "to the root" because a
#: symlinked or bind-mounted tree can otherwise walk a very long way, and every
#: level is a stat call on a hook's critical path.
MAX_WALK_UP = 32

#: The entry whose presence ENDS the walk, after that directory is inspected.
#: A config outside the repo describes some other repo's estate.
REPO_MARKER = ".git"

#: The auto-detected state file name.
STATE_NAME = "terraform.tfstate"

#: The directory whose copy of :data:`STATE_NAME` is REFUSED; see the module
#: docstring on why a backend stub looks exactly like a clean empty estate.
BACKEND_DIR = ".terraform"

#: The :data:`gcp_grounding.baseline.HOWS` spelling a config-supplied target
#: carries into the explain surface.
TARGET_HOW = "config-map"

#: Environment variable naming the compiled requirements. Defined HERE, in the
#: settings layer that owns the ``requirements`` field, and re-exported by the
#: CLI: ``requirements`` has no ``SourceOptions`` slot, so
#: :func:`gcp_grounding.sources.from_env` cannot resolve it — the environment
#: layer below reads it directly, which is what makes an env-supplied value
#: report the ``env`` origin like every other env-supplied setting.
REQUIREMENTS_ENV = "GCP_GROUNDING_REQUIREMENTS"

#: Config key → the settings field it supplies. THE ONE TABLE: the config file
#: spells the snapshot ``snapshot`` and the drift mode ``drift`` while
#: ``SourceOptions`` calls them ``primary`` and ``drift_policy``, and a second
#: copy of that correspondence is a second place for a field to go missing.
CONFIG_KEYS = {
    "snapshot": "primary",
    "precedence": "precedence",
    "max_age": "max_age",
    "drift": "drift_policy",
    "targets": "targets",
    "requirements": "requirements",
    "provider_schema": "provider_schema",
    "schema_policy": "schema_policy",
}

#: Key inside the ``terraform`` object → the settings field it supplies.
TERRAFORM_KEYS = {
    "state": "terraform_state",
    "plan": "terraform_plan",
    "config_dir": "terraform_dir",
}

#: The path-list fields, read from ``sources`` rather than restated.
_PATH_LIST_FIELDS = frozenset(sources.PATH_FIELDS)

#: Every ``SourceOptions`` field, DERIVED. A field added there appears here
#: without an edit, which is what makes ``to_source_options`` a field access.
OPTION_FIELDS = tuple(f.name for f in dataclasses.fields(SourceOptions))

#: Every field :func:`resolve_settings` tracks an origin for: the source
#: options, plus the two settings-only fields.
SETTINGS_FIELDS = OPTION_FIELDS + ("targets", "requirements")

#: The origin labels, strongest first. The ``config`` label is followed by the
#: config file's path, so a reader can see WHICH file supplied the value.
ORIGIN_LABELS = ("cli", "env", "config", "auto", "default")

_DEFAULTS: dict[str, Any] = {name: getattr(SourceOptions(), name)
                             for name in OPTION_FIELDS}
_DEFAULTS["targets"] = {}
_DEFAULTS["requirements"] = ""


def remote_backend_problem(path: str) -> str:
    """THE ONE remote-backend message, so the CLI and the gate say the same
    thing about the same refusal."""
    return (f"the only {STATE_NAME} found is {path}, which lives under a "
            f"{BACKEND_DIR}/ directory - with a gcs or s3 backend that file holds "
            f"only the backend configuration 'terraform init' recorded and has no "
            f"'resources' array at all, which is indistinguishable from a clean "
            f"EMPTY estate. It was NOT auto-detected as a state source: run "
            f"'terraform state pull > {STATE_NAME}' beside your configuration, or "
            f"name a state file explicitly in {CONFIG_NAMES[0]}")


# -- what a parsed config is --------------------------------------------------


@dataclass(frozen=True)
class Config:
    """One parsed config file: where it lives, and the settings it supplies.

    ``values`` is keyed by :data:`SETTINGS_FIELDS` — the field names
    ``SourceOptions`` itself uses — and holds only the keys the document
    actually carried. Storing them under the SETTINGS spelling rather than
    re-spelling them at resolve time is deliberate: the config-key-to-field
    correspondence exists once, in :data:`CONFIG_KEYS` and
    :data:`TERRAFORM_KEYS`, and nowhere else.

    Every path in it is ALREADY RESOLVED against :attr:`directory`.
    """

    path: str
    directory: str
    values: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", dict(self.values))

    def get(self, name: str, default: Any = None) -> Any:
        """This config's value for a settings field, or *default*."""
        return self.values.get(name, default)


@dataclass(frozen=True)
class Auto:
    """What auto-detection found. State files ONLY — never a directory and
    never a plan; see the module docstring."""

    terraform_state: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "terraform_state", tuple(self.terraform_state))


@dataclass(frozen=True)
class Settings:
    """The resolved settings, plus which layer supplied each field.

    It WRAPS a :class:`~gcp_grounding.sources.SourceOptions` and does not
    restate its fields. ``origins`` is TOTAL over :data:`SETTINGS_FIELDS`, so an
    untouched field reports ``default`` rather than being missing from the map —
    the explain surface must be able to print a line for every input.

    ONE SPELLING IS SHARED WITH ``SourceOptions`` AND MEANS SOMETHING ELSE:
    ``Settings.origins`` is the per-field ORIGIN LABEL map, while
    ``settings.options.origins`` is the snapshot's sidecar PATH. Both names are
    fixed by their own designs; reading one as the other is the mistake, so a
    test pins the collision rather than leaving it to be rediscovered.
    """

    options: SourceOptions = field(default_factory=SourceOptions)
    origins: Mapping[str, str] = field(default_factory=dict)
    targets: Mapping[str, TargetRef] = field(default_factory=dict)
    requirements: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "origins", dict(self.origins))
        object.__setattr__(self, "targets", dict(self.targets))

    def origin_of(self, name: str) -> str:
        """Which layer supplied *name*. ``default`` for anything nobody set."""
        return self.origins.get(name, "default")


# -- the walk -----------------------------------------------------------------


def walk_up(start_path: str | os.PathLike[str]) -> tuple[str, ...]:
    """The directories to inspect for *start_path*, nearest first.

    At most :data:`MAX_WALK_UP` levels, and STOPPING AFTER the first directory
    that contains a :data:`REPO_MARKER` entry — after, so a config committed at
    the repo root IS found while one in the parent of the checkout is not. A
    config outside the repo describes some other repo's estate, and grounding a
    change against it is a confident answer about the wrong thing.
    """
    start = os.path.abspath(os.fspath(start_path))
    directory = start if os.path.isdir(start) else os.path.dirname(start)
    out: list[str] = []
    for _ in range(MAX_WALK_UP):
        out.append(directory)
        if os.path.exists(os.path.join(directory, REPO_MARKER)):
            break
        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent
    return tuple(out)


# -- parsing ------------------------------------------------------------------


def _resolve(value: str, directory: str) -> str:
    """*value* against the CONFIG FILE's directory, never the cwd."""
    if os.path.isabs(value):
        return os.path.normpath(value)
    return os.path.normpath(os.path.join(directory, value))


def _one_path(value: Any, key: str, directory: str, problems: list[str]) -> str:
    if not isinstance(value, str) or not value.strip():
        problems.append(f"'{key}' must be a non-empty path string, got "
                        f"{type(value).__name__}")
        return ""
    return _resolve(value.strip(), directory)


def _path_list(value: Any, key: str, directory: str,
               problems: list[str]) -> tuple[str, ...]:
    """A path LIST field. A lone string is one path — never a string iterated
    into characters, which is the most destructive way this could be got
    wrong."""
    if isinstance(value, str):
        items: list[Any] = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        problems.append(f"'{key}' must be a list of paths, got "
                        f"{type(value).__name__}")
        return ()
    out: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item.strip():
            problems.append(f"'{key}' holds {item!r}, which is not a non-empty "
                            f"path string")
            continue
        out.append(_resolve(item.strip(), directory))
    return tuple(out)


def _targets(value: Any, directory: str,
             problems: list[str]) -> dict[str, TargetRef]:
    """The ``targets`` map: proposal path → ``<domain>:<key>``.

    A malformed entry is a PROBLEM and NO TARGET. Nothing here guesses a domain
    from the key or a key from the path: a near-miss target silently redefines
    what the widening check compares against, which is worse than having none.
    """
    if not isinstance(value, Mapping):
        problems.append(f"'targets' must be a mapping from a proposal path to a "
                        f"'<domain>:<key>' string, got {type(value).__name__}")
        return {}
    out: dict[str, TargetRef] = {}
    for raw_path, raw_target in value.items():
        if not isinstance(raw_path, str) or not raw_path.strip():
            problems.append(f"'targets' key {raw_path!r} is not a non-empty "
                            f"proposal path")
            continue
        if not isinstance(raw_target, str) or ":" not in raw_target:
            problems.append(
                f"'targets[{raw_path}]' is {raw_target!r}, which is not a "
                f"'<domain>:<key>' string; the domain is one of "
                f"{list(provenance.CATEGORIES)} and NO domain is guessed from the "
                f"key")
            continue
        category, _, key = raw_target.partition(":")
        category, key = category.strip(), key.strip()
        try:
            out[_resolve(raw_path.strip(), directory)] = TargetRef(
                category=category, key=key, how=TARGET_HOW)
        except ValueError as exc:
            problems.append(f"'targets[{raw_path}]' = {raw_target!r}: {exc}")
    return out


def parse_config(data: Any, *, path: str) -> tuple[Config | None, tuple[str, ...]]:
    """*data* as a :class:`Config`, or ``None`` plus EVERY problem found.

    Strict at both levels: an unrecognized top-level key and an unrecognized key
    inside ``terraform`` are each named. Every problem is collected rather than
    only the first, so one bad file is fixed in one pass.
    """
    fspath = os.path.abspath(path)
    directory = os.path.dirname(fspath)
    problems: list[str] = []
    if not isinstance(data, Mapping):
        return None, (f"{fspath}: a config must be a mapping, got "
                      f"{type(data).__name__}",)

    known = {"schema", "terraform", *CONFIG_KEYS}
    unrecognized = sorted(set(map(str, data)) - known)
    if unrecognized:
        problems.append(f"unrecognized config key(s) {unrecognized} - a typo must "
                        f"not silently demote a setting; expected only "
                        f"{sorted(known)}")

    schema = data.get("schema")
    if schema != CONFIG_SCHEMA:
        problems.append(f"'schema' must be exactly {CONFIG_SCHEMA!r}, found "
                        f"{schema!r}")

    values: dict[str, Any] = {}
    for key, name in CONFIG_KEYS.items():
        if key not in data:
            continue
        raw = data[key]
        if key == "targets":
            values[name] = _targets(raw, directory, problems)
        elif key == "provider_schema":
            # A path LIST like the terraform keys — one captured schema per
            # provider — resolved against the config file's own directory.
            values[name] = _path_list(raw, key, directory, problems)
        elif key in ("snapshot", "requirements"):
            values[name] = _one_path(raw, key, directory, problems)
        else:
            if not isinstance(raw, str) or not raw.strip():
                problems.append(f"'{key}' must be a non-empty string, got "
                                f"{type(raw).__name__}")
                continue
            values[name] = raw.strip()

    terraform = data.get("terraform")
    if terraform is not None:
        if not isinstance(terraform, Mapping):
            problems.append(f"'terraform' must be a mapping of "
                            f"{sorted(TERRAFORM_KEYS)}, got "
                            f"{type(terraform).__name__}")
        else:
            nested = sorted(set(map(str, terraform)) - set(TERRAFORM_KEYS))
            if nested:
                problems.append(f"unrecognized key(s) {nested} inside 'terraform' - "
                                f"a typo must not silently demote a setting; "
                                f"expected only {sorted(TERRAFORM_KEYS)}")
            for key, name in TERRAFORM_KEYS.items():
                if key in terraform:
                    values[name] = _path_list(terraform[key],
                                              f"terraform.{key}", directory,
                                              problems)

    # Every setting is validated HERE, where the config path is still in hand.
    # A precedence typo that quietly restored the default would change what the
    # gate enforces with nothing saying so.
    precedence = values.get("precedence")
    if precedence:
        try:
            merge.parse_policy(precedence)
        except ValueError as exc:
            problems.append(f"'precedence' {precedence!r}: {exc}")
    max_age = values.get("max_age")
    if max_age:
        try:
            freshness.parse_duration(max_age)
        except ValueError as exc:
            problems.append(f"'max_age' {max_age!r}: {exc}")
    mode = values.get("drift_policy")
    if mode and mode not in drift.DRIFT_POLICIES:
        problems.append(f"'drift' {mode!r} is not one of "
                        f"{list(drift.DRIFT_POLICIES)}")
    policy = values.get("schema_policy")
    if policy and policy not in provider_schema.SCHEMA_POLICIES:
        problems.append(f"'schema_policy' {policy!r} is not one of "
                        f"{list(provider_schema.SCHEMA_POLICIES)}")

    if problems:
        # NEVER A PARTIAL CONFIG. Half a parsed file is a setting silently
        # missing, which is exactly what the strict parse exists to prevent.
        return None, tuple(f"{fspath}: {problem}" for problem in problems)
    return Config(path=fspath, directory=directory, values=values), ()


def load_config(path: str | os.PathLike[str]
                ) -> tuple[Config | None, tuple[str, ...]]:
    """One config file from disk. Never raises."""
    fspath = os.path.abspath(os.fspath(path))
    try:
        with open(fspath, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        return None, (f"{fspath}: {type(exc).__name__}: {exc}",)
    return parse_config(data, path=fspath)


# -- discovery ----------------------------------------------------------------


def discover(start_path: str | os.PathLike[str], *,
             env: Mapping[str, str] | None = None
             ) -> tuple[Config | None, tuple[str, ...]]:
    """The config governing *start_path*, or ``None``, plus any problems.

    :data:`CONFIG_ENV` short-circuits the walk. Otherwise the first config found
    walking up from the start path's directory wins, and a config that fails to
    parse is the answer — ``None`` plus its problems — rather than a reason to
    keep climbing: a broken config silently replaced by a grandparent's is a run
    that used a state file the operator never named. ``(None, ())`` therefore
    means "no config file was found" and ``(None, problems)`` means "found but
    refused" — callers use that distinction to suppress auto-detection for a
    refused config exactly as they would for a parsed one.

    NEVER RAISES. A discovery layer that can crash is a gate that can crash on a
    file it was only asked to look near.
    """
    environ = os.environ if env is None else env
    try:
        override = (environ.get(CONFIG_ENV) or "").strip()
        if override:
            logger.debug("config discovery short-circuited by $%s=%s",
                         CONFIG_ENV, override)
            return load_config(override)
        for directory in walk_up(start_path):
            for name in CONFIG_NAMES:
                candidate = os.path.join(directory, name)
                if os.path.isfile(candidate):
                    return load_config(candidate)
        return None, ()
    except Exception as exc:                # noqa: BLE001 - never raise upward
        logger.debug("config discovery from %s raised %s", start_path,
                     type(exc).__name__, exc_info=True)
        return None, (f"config discovery from {start_path} failed "
                      f"({type(exc).__name__}: {exc}) - no config file was used",)


def auto_detect(start_path: str | os.PathLike[str]
                ) -> tuple[Auto | None, tuple[str, ...]]:
    """A sibling ``terraform.tfstate`` from the same walk, or ``None``.

    The backend stub under :data:`BACKEND_DIR` is REFUSED and, when it is the
    only candidate, reported through :func:`remote_backend_problem`. Never a
    directory and never a plan: see the module docstring.

    NEVER RAISES.
    """
    try:
        directories = walk_up(start_path)
        for directory in directories:
            if os.path.basename(directory) == BACKEND_DIR:
                continue
            sibling = os.path.join(directory, STATE_NAME)
            if os.path.isfile(sibling):
                logger.debug("auto-detected state source %s", sibling)
                return Auto(terraform_state=(sibling,)), ()
        for directory in directories:
            stub = os.path.join(directory, BACKEND_DIR, STATE_NAME)
            if os.path.isfile(stub):
                return None, (remote_backend_problem(stub),)
        return None, ()
    except Exception as exc:                # noqa: BLE001 - never raise upward
        logger.debug("auto-detection from %s raised %s", start_path,
                     type(exc).__name__, exc_info=True)
        return None, (f"terraform state auto-detection from {start_path} failed "
                      f"({type(exc).__name__}: {exc}) - no source was detected",)


# -- precedence ---------------------------------------------------------------


def _supplied(value: Any) -> bool:
    """Whether a layer actually SUPPLIED this field. An empty tuple, string or
    mapping is nobody having chosen, which is what lets the next layer down
    answer."""
    if value is None:
        return False
    if isinstance(value, (str, bytes, tuple, list, Mapping)):
        return bool(value)
    return True


def _cli_layer(cli: Any) -> Mapping[str, Any]:
    """The flag layer: a mapping keyed by :data:`SETTINGS_FIELDS`, or a
    ``SourceOptions`` a caller already built.

    An unknown key raises :class:`TypeError`, exactly as
    :func:`gcp_grounding.sources.from_env` does for an unknown override: a
    typo'd keyword silently dropped is the same invisible failure this module
    exists to prevent, one layer up.
    """
    if cli is None:
        return {}
    if isinstance(cli, SourceOptions):
        return {name: getattr(cli, name) for name in OPTION_FIELDS}
    if not isinstance(cli, Mapping):
        raise TypeError(f"resolve_settings(cli=...) takes a mapping or a "
                        f"SourceOptions, got {type(cli).__name__}")
    unknown = sorted(set(map(str, cli)) - set(SETTINGS_FIELDS))
    if unknown:
        raise TypeError(f"resolve_settings got unknown cli setting(s) {unknown}; "
                        f"the settings are {sorted(SETTINGS_FIELDS)}")
    return dict(cli)


def _env_layer(env: Mapping[str, str] | None) -> Mapping[str, Any]:
    """The environment layer, resolved by THE ONE env resolver. A second one
    here is a second place to apply a different precedence.

    ``requirements`` is the one field read directly: it has no ``SourceOptions``
    slot for :func:`gcp_grounding.sources.from_env` to fill, and resolving
    :data:`REQUIREMENTS_ENV` anywhere else would either misattribute the value's
    origin or let a config file outrank the environment for this one setting.
    """
    options = sources.from_env(env)
    layer: dict[str, Any] = {name: getattr(options, name)
                             for name in OPTION_FIELDS}
    environ = os.environ if env is None else env
    raw = environ.get(REQUIREMENTS_ENV)
    if raw and raw.strip():
        layer["requirements"] = raw.strip()
    return layer


def _config_layer(config: Config | None) -> Mapping[str, Any]:
    return dict(config.values) if config is not None else {}


def _auto_layer(auto: Auto | None) -> Mapping[str, Any]:
    return {"terraform_state": auto.terraform_state} if auto is not None else {}


def resolve_settings(*, cli: Any = None, env: Mapping[str, str] | None = None,
                     config: Config | None = None,
                     auto: Auto | None = None) -> Settings:
    """CLI over env over config-file over auto-detected over defaults, with the
    winning layer recorded per field.

    The origin labels are :data:`ORIGIN_LABELS`, with ``config`` followed by the
    config file's own path so a reader can see WHICH file supplied a value. The
    map is total: a field nobody set reports ``default``.
    """
    layers = (
        ("cli", _cli_layer(cli)),
        ("env", _env_layer(env)),
        (f"config {config.path}" if config is not None else "config",
         _config_layer(config)),
        ("auto", _auto_layer(auto)),
    )
    chosen: dict[str, Any] = {}
    origins: dict[str, str] = {}
    for name in SETTINGS_FIELDS:
        for label, values in layers:
            value = values.get(name)
            if _supplied(value):
                chosen[name] = value
                origins[name] = label
                break
        else:
            chosen[name] = _DEFAULTS[name]
            origins[name] = "default"
    options = SourceOptions(**{name: chosen[name] for name in OPTION_FIELDS})
    logger.debug("resolved settings: %s", ", ".join(
        f"{name}={origins[name]}" for name in SETTINGS_FIELDS))
    return Settings(options=options, origins=origins,
                    targets=chosen["targets"], requirements=chosen["requirements"])


def _stamp(as_of: Any) -> str:
    return as_of.isoformat() if isinstance(as_of, datetime) else str(as_of)


def to_source_options(settings: Settings, *, as_of: Any) -> SourceOptions:
    """*settings*' wrapped options, carrying the INJECTED clock.

    A FIELD ACCESS plus one field, not a translation: ``Settings`` wraps a
    ``SourceOptions`` precisely so that a field added there arrives here without
    an edit and cannot be silently dropped.

    THIS IS THE ONLY WAY A CLI-BEARING CALLER BUILDS OPTIONS.
    :func:`gcp_grounding.sources.from_env` knows nothing about a config file or
    auto-detection, so using it on a path that also promises discovery ignores
    whatever the user wrote in the config file — with no error at all.

    *as_of* is keyword-only and REQUIRED: the clock is resolved once per run at
    the gate or CLI boundary through :func:`gcp_grounding.freshness.resolve_now`
    and injected downward, and passing ``None`` is the explicit way to say the
    run pins no clock.
    """
    if as_of is None:
        return settings.options
    return dataclasses.replace(settings.options, now=_stamp(as_of))


def settings_for(start_path: str | os.PathLike[str], *, cli: Any = None,
                 env: Mapping[str, str] | None = None
                 ) -> tuple[Settings, tuple[str, ...]]:
    """The settings governing *start_path*, plus every problem found.

    Discovery first; auto-detection runs ONLY when no config file was found —
    a found-but-REFUSED config (``discover`` returned ``None`` with problems)
    also suppresses detection, because an operator who wrote a config has
    already said what the sources are and a detected file appearing beside it
    would be a source they never named. That the config failed to parse does
    not change who said what: the refusal surfaces as problems, the settings
    fall to their defaults, and no source the operator never named is guessed
    into the run.
    """
    config, problems = discover(start_path, env=env)
    auto: Auto | None = None
    if config is None and not problems:
        auto, detected = auto_detect(start_path)
        problems = problems + detected
    return resolve_settings(cli=cli, env=env, config=config, auto=auto), problems
