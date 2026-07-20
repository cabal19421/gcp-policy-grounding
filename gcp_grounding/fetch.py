"""Live snapshot fetchers — the one opt-in, network-touching module.

Populates a :class:`~gcp_grounding.knowledge.GcpSnapshot` from a live GCP
estate:

- roles + their permissions via the IAM API (``roles.list`` with the FULL
  view, ``roles.get`` to backfill entries the list view leaves bare) for
  predefined roles plus any org/project custom-role parents;
- an explicit permission enumeration via IAM ``queryTestablePermissions``
  (the only source :mod:`~gcp_grounding.knowledge` accepts as proof of
  *absence* — the union of role-included permissions deliberately is not);
- org-policy constraint names + value types via the Org Policy v2 API;
- principals via Cloud Asset Inventory ``searchAllIamPolicies``;
- Terraform resource types via a cached ``terraform providers schema -json``
  — the sole source of snapshot ``resource_types``, since that category is
  the terraform provider vocabulary :mod:`~gcp_grounding.tf_claims` emits
  and the reasoner checks. CAI asset types (``assets.list``, available
  standalone via :func:`fetch_asset_types`) name a different namespace and
  feed no snapshot category.

Every network call sits behind a function taking a *client* argument — an
object with the same call shape as a ``googleapiclient`` discovery Resource
(``client.roles().list(...).execute()``). Tests pass mocks; live callers pass
:func:`default_client`, which resolves the optional SDK at call time via
:mod:`importlib` (the same optional-dependency pattern ``core/solver.py``
uses for z3). No GCP SDK is imported at module load — the offline grounding
path and the test suite stay SDK-free, credential-free, and network-free.

Categories a caller does not request are left uncaptured (``None``) so the
knowledge base keeps answering :data:`~gcp_grounding.knowledge.UNKNOWN` for
them — a partial capture must never manufacture false "ungrounded" evidence.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Iterator

from .core.log import fmt_cmd, get_logger
from .knowledge import GcpSnapshot

logger = get_logger(__name__)

__all__ = [
    "MissingDependencyError",
    "capture_snapshot",
    "default_client",
    "fetch_asset_types",
    "fetch_constraints",
    "fetch_permissions",
    "fetch_principals",
    "fetch_resource_types",
    "fetch_roles",
    "fresh_captured_at",
    "write_snapshot",
]


class MissingDependencyError(RuntimeError):
    """A live fetch was requested but the optional GCP SDK is not installed."""


def fresh_captured_at() -> str:
    """The current UTC instant in the snapshot's ISO-8601 ``...Z`` form."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── clients ───────────────────────────────────────────────────────────────────

# APIs this module knows how to talk to, with their current versions.
_API_VERSIONS = {"iam": "v1", "orgpolicy": "v2", "cloudasset": "v1"}


def default_client(api: str, version: str | None = None) -> Any:
    """Build a live discovery client for *api* ("iam" / "orgpolicy" /
    "cloudasset"), resolving the optional SDK only now — never at import.

    Uses Application Default Credentials. Anything accepted here can be
    replaced by a test double with the same ``.collection().method(...)
    .execute()`` shape; nothing else in this module touches the SDK.
    """
    resolved = version or _API_VERSIONS.get(api)
    if resolved is None:
        raise ValueError(f"unknown API {api!r} and no explicit version given; "
                         f"known APIs: {sorted(_API_VERSIONS)}")
    if importlib.util.find_spec("googleapiclient") is None:
        raise MissingDependencyError(
            f"building a live {api!r} client needs the optional SDK: "
            f"pip install google-api-python-client — offline grounding against "
            f"a frozen snapshot needs no SDK at all")
    discovery = importlib.import_module("googleapiclient.discovery")
    logger.debug("building live discovery client %s/%s", api, resolved)
    return discovery.build(api, resolved, cache_discovery=False)


def _paginate(list_call: Callable[..., Any], item_key: str,
              **params: Any) -> Iterator[dict[str, Any]]:
    """Yield *item_key* items across every ``nextPageToken`` page of a
    discovery-style list method."""
    token: str | None = None
    while True:
        call_params = dict(params)
        if token:
            call_params["pageToken"] = token
        page = list_call(**call_params).execute() or {}
        yield from page.get(item_key, ())
        token = page.get("nextPageToken")
        if not token:
            return


# ── IAM: roles + permissions ──────────────────────────────────────────────────

def _roles_collection(iam: Any, parent: str | None) -> Any:
    if parent is None:
        return iam.roles()
    if parent.startswith("organizations/"):
        return iam.organizations().roles()
    if parent.startswith("projects/"):
        return iam.projects().roles()
    raise ValueError(f"custom-role parent {parent!r} must look like "
                     f"'organizations/<id>' or 'projects/<id>' — IAM custom "
                     f"roles live nowhere else")


def fetch_roles(iam: Any, *,
                custom_role_parents: Iterable[str] = ()) -> dict[str, dict[str, Any]]:
    """All predefined roles plus the custom roles under each parent, as
    snapshot-ready records (``title``/``stage``/``included_permissions``).

    Lists with ``view="FULL"`` so permissions arrive inline; an entry the
    list view leaves without ``includedPermissions`` is backfilled with one
    ``roles.get``. Deleted roles are skipped — a snapshot must not bless a
    binding onto a role that no longer grants anything.
    """
    parents = (None, *tuple(custom_role_parents))
    # Resolve every collection first so a malformed parent fails fast,
    # before any page has been pulled.
    collections = [(parent, _roles_collection(iam, parent)) for parent in parents]
    roles: dict[str, dict[str, Any]] = {}
    for parent, collection in collections:
        params: dict[str, Any] = {"view": "FULL"}
        if parent is not None:
            params["parent"] = parent
        for role in _paginate(collection.list, "roles", **params):
            name = role.get("name")
            if not name:
                logger.warning("roles.list (parent=%r) returned an entry with no "
                               "name — skipped", parent)
                continue
            if role.get("deleted"):
                logger.debug("skipping deleted role %s", name)
                continue
            if "includedPermissions" not in role:
                logger.debug("list view omitted permissions for %s — backfilling "
                             "via roles.get", name)
                role = collection.get(name=name).execute() or {}
            record: dict[str, Any] = {
                "included_permissions": sorted(role.get("includedPermissions") or ()),
            }
            for field in ("title", "stage", "description"):
                if role.get(field):
                    record[field] = role[field]
            roles[name] = record
    logger.debug("fetched %d roles across %d parent scope(s)", len(roles), len(parents))
    return roles


def fetch_permissions(iam: Any,
                      full_resource_names: Iterable[str]) -> frozenset[str]:
    """The explicit permission enumeration: ``queryTestablePermissions``
    against each full resource name (e.g.
    ``//cloudresourcemanager.googleapis.com/projects/acme-prod``).

    This — not the union of role-included permissions — is what the
    knowledge base treats as licence to answer ``False`` for a permission
    it has never seen.
    """
    query = iam.permissions().queryTestablePermissions
    permissions: set[str] = set()
    for resource in full_resource_names:
        token: str | None = None
        while True:
            body: dict[str, Any] = {"fullResourceName": resource}
            if token:
                body["pageToken"] = token
            page = query(body=body).execute() or {}
            permissions.update(p["name"] for p in page.get("permissions", ())
                               if p.get("name"))
            token = page.get("nextPageToken")
            if not token:
                break
    return frozenset(permissions)


# ── Org Policy: constraints ───────────────────────────────────────────────────

def _constraints_collection(orgpolicy: Any, parent: str) -> Any:
    for prefix, accessor in (("organizations/", "organizations"),
                             ("folders/", "folders"),
                             ("projects/", "projects")):
        if parent.startswith(prefix):
            return getattr(orgpolicy, accessor)().constraints()
    raise ValueError(f"org-policy parent {parent!r} must look like "
                     f"'organizations/<id>', 'folders/<id>' or 'projects/<id>'")


def _short_constraint_name(name: str) -> str:
    # The API returns parent-qualified names ("organizations/123/constraints/x");
    # snapshots and policy files use the parentless "constraints/x" form.
    if "/constraints/" in name:
        return "constraints/" + name.rsplit("/constraints/", 1)[1]
    return name if name.startswith("constraints/") else f"constraints/{name}"


def fetch_constraints(orgpolicy: Any, parent: str) -> dict[str, dict[str, Any]]:
    """Org-policy constraints available under *parent*, keyed by their short
    ``constraints/...`` name, each with the ``value_type`` the contradiction
    check needs ("boolean" / "list").

    A constraint that is neither boolean- nor list-typed is still recorded
    (``value_type: "unknown"``): it exists, and dropping it would turn a real
    name into a false "ungrounded" downstream.
    """
    collection = _constraints_collection(orgpolicy, parent)
    constraints: dict[str, dict[str, Any]] = {}
    for entry in _paginate(collection.list, "constraints", parent=parent):
        name = entry.get("name")
        if not name:
            logger.warning("constraints.list under %s returned an entry with no "
                           "name — skipped", parent)
            continue
        short = _short_constraint_name(name)
        if "booleanConstraint" in entry:
            value_type = "boolean"
        elif "listConstraint" in entry:
            value_type = "list"
        else:
            value_type = "unknown"
            logger.debug("constraint %s is neither boolean- nor list-typed — "
                         "recorded with value_type='unknown'", short)
        record: dict[str, Any] = {"value_type": value_type}
        if entry.get("description"):
            record["description"] = entry["description"]
        constraints[short] = record
    logger.debug("fetched %d constraints under %s", len(constraints), parent)
    return constraints


# ── Cloud Asset Inventory: principals + resource inventory ────────────────────

def fetch_principals(asset: Any, scope: str) -> frozenset[str]:
    """Every principal bound anywhere in *scope* (a ``projects/``,
    ``folders/`` or ``organizations/`` name), via CAI
    ``searchAllIamPolicies`` — deduplicated binding members
    ("user:…", "serviceAccount:…", "group:…", …)."""
    principals: set[str] = set()
    search = asset.v1().searchAllIamPolicies
    for result in _paginate(search, "results", scope=scope):
        for binding in (result.get("policy") or {}).get("bindings", ()):
            principals.update(m for m in binding.get("members", ()) if m)
    logger.debug("fetched %d distinct principals in %s", len(principals), scope)
    return frozenset(principals)


def fetch_asset_types(asset: Any, parent: str) -> frozenset[str]:
    """The asset types actually present under *parent* (e.g.
    ``compute.googleapis.com/Instance``), via CAI ``assets.list``.

    Standalone only: asset types are not terraform resource-type names, so
    :func:`capture_snapshot` never folds them into snapshot
    ``resource_types`` — that would mark the category captured with the
    wrong vocabulary and manufacture false "ungrounded" evidence."""
    types: set[str] = set()
    for entry in _paginate(asset.assets().list, "assets",
                           parent=parent, contentType="RESOURCE"):
        if entry.get("assetType"):
            types.add(entry["assetType"])
    logger.debug("fetched %d distinct asset types under %s", len(types), parent)
    return frozenset(types)


# ── Terraform: provider resource types ────────────────────────────────────────

def _run_terraform_schema(terraform_dir: str | os.PathLike[str] | None) -> str:
    cmd = ["terraform", "providers", "schema", "-json"]
    logger.debug("%s", fmt_cmd(cmd, cwd=terraform_dir))
    try:
        proc = subprocess.run(cmd, cwd=terraform_dir, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "the 'terraform' executable is not on PATH — install terraform, or "
            "pass cache_path pointing at a saved 'terraform providers schema "
            "-json' dump") from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"'terraform providers schema -json' failed (exit {proc.returncode}) "
            f"in {terraform_dir or os.getcwd()}: {proc.stderr.strip()}")
    return proc.stdout


def fetch_resource_types(terraform_dir: str | os.PathLike[str] | None = None, *,
                         cache_path: str | os.PathLike[str] | None = None,
                         runner: Callable[..., str] | None = None) -> frozenset[str]:
    """Terraform resource type names (``google_project_iam_binding``, …) from
    ``terraform providers schema -json`` run in *terraform_dir*.

    When *cache_path* exists its content is used verbatim and terraform is
    not run; after a live run the raw schema JSON is written there, so
    repeated captures reuse one schema dump. *runner* replaces the subprocess
    (tests; it receives *terraform_dir* and returns the schema JSON text).
    """
    text: str | None = None
    source = "'terraform providers schema -json' output"
    if cache_path is not None and os.path.exists(cache_path):
        with open(cache_path, encoding="utf-8") as fh:
            text = fh.read()
        source = f"terraform schema cache {cache_path}"
        logger.debug("reusing %s", source)
    live = text is None
    if live:
        text = (runner or _run_terraform_schema)(terraform_dir)
    try:
        schema = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source} is not valid JSON: {exc}") from exc
    if live and cache_path is not None:
        with open(cache_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        logger.debug("terraform provider schema cached at %s", cache_path)
    types: set[str] = set()
    for provider_schema in (schema.get("provider_schemas") or {}).values():
        types.update((provider_schema or {}).get("resource_schemas") or {})
    logger.debug("terraform schema enumerates %d resource types", len(types))
    return frozenset(types)


# ── capture orchestration ─────────────────────────────────────────────────────

def write_snapshot(snapshot: GcpSnapshot, path: str | os.PathLike[str]) -> None:
    """Serialize *snapshot* to *path* deterministically (sorted keys, so
    successive captures diff cleanly)."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True) + "\n")
    logger.debug("wrote snapshot to %s (captured_at=%s)", path, snapshot.captured_at)


def capture_snapshot(*, iam: Any = None, orgpolicy: Any = None, asset: Any = None,
                     custom_role_parents: Iterable[str] = (),
                     permission_resources: Iterable[str] = (),
                     orgpolicy_parent: str | None = None,
                     asset_scope: str | None = None,
                     terraform_dir: str | os.PathLike[str] | None = None,
                     schema_cache: str | os.PathLike[str] | None = None,
                     terraform_runner: Callable[..., str] | None = None,
                     captured_at: str | None = None,
                     out_path: str | os.PathLike[str] | None = None) -> GcpSnapshot:
    """Capture a fresh :class:`GcpSnapshot` from whichever sources were
    configured, stamp it with a fresh ``captured_at`` (or the one given),
    and optionally write it to *out_path*.

    Only requested categories are captured; the rest stay ``None`` so the
    knowledge base answers UNKNOWN for them instead of a false absence.
    A half-configured source (client without its parent/scope, or vice
    versa) raises ValueError — silently skipping a category the caller
    thought they requested would poison every downstream verdict.

    ``resource_types`` comes from the terraform schema alone and is marked
    captured only when that schema was actually requested: it is the
    terraform provider vocabulary, and unioning CAI asset types into it
    would flag the category as enumerated with the wrong namespace — a
    partial capture manufacturing false "ungrounded" evidence.
    """
    custom_role_parents = tuple(custom_role_parents)
    permission_resources = tuple(permission_resources)
    if (custom_role_parents or permission_resources) and iam is None:
        raise ValueError("custom_role_parents/permission_resources given but no "
                         "iam client to fetch them with")
    if (orgpolicy is None) != (orgpolicy_parent is None):
        raise ValueError("org-policy capture needs both an orgpolicy client and "
                         "an orgpolicy_parent")
    if (asset is None) != (asset_scope is None):
        raise ValueError("principal capture needs both a Cloud Asset Inventory "
                         "client and an asset_scope")

    data: dict[str, Any] = {"captured_at": captured_at or fresh_captured_at()}
    if iam is not None:
        data["roles"] = fetch_roles(iam, custom_role_parents=custom_role_parents)
        if permission_resources:
            data["permissions"] = sorted(fetch_permissions(iam, permission_resources))
    if orgpolicy is not None:
        data["constraints"] = fetch_constraints(orgpolicy, orgpolicy_parent)
    if asset is not None:
        data["principals"] = sorted(fetch_principals(asset, asset_scope))
    if (terraform_dir is not None or terraform_runner is not None
            or schema_cache is not None):
        data["resource_types"] = sorted(fetch_resource_types(
            terraform_dir, cache_path=schema_cache, runner=terraform_runner))

    snapshot = GcpSnapshot.from_dict(data)
    logger.debug("captured snapshot (captured_at=%s, categories=%s)",
                 snapshot.captured_at,
                 ",".join(snapshot.captured_categories()) or "none")
    if out_path is not None:
        write_snapshot(snapshot, out_path)
    return snapshot
