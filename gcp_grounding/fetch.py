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
- principals via Cloud Asset Inventory ``searchAllIamPolicies``
  (:func:`fetch_principals`), and — from the SAME single pass over that estate —
  the full per-resource IAM bindings (:func:`fetch_iam_bindings`, role + members
  + verbatim ``condition``), the two available together via
  :func:`fetch_principals_and_bindings` so the estate is paginated once;
- the resource hierarchy via the Cloud Resource Manager v3 API
  (:func:`fetch_hierarchy`): a breadth-first ``folders.list`` / ``projects.list``
  walk from an ``organizations/<id>`` or ``folders/<id>`` root into the
  ``resource_hierarchy`` schema, bounded by a ``max_depth`` and a visited set.
  It returns a ``truncated`` flag, and :func:`capture_snapshot` REFUSES to mark
  ``resource_hierarchy`` captured when the walk truncated — a partial hierarchy
  presented as complete would let ``hierarchy_names()`` prove ABSENCE for every
  out-of-scope node and manufacture false ``ungrounded`` blocks;
- Terraform resource types via a cached ``terraform providers schema -json``
  — the sole source of snapshot ``resource_types``, since that category is
  the terraform provider vocabulary :mod:`~gcp_grounding.tf_claims` emits
  and the reasoner checks. CAI asset types (``assets.list``, available
  standalone via :func:`fetch_asset_types`) name a different namespace and
  feed no snapshot category.
- the Compute-side estate via the Compute Engine v1 API: VPC networks
  (:func:`fetch_networks`) and subnetworks (:func:`fetch_subnetworks`), each
  self-link normalized to its ``projects/.../networks``/``.../subnetworks``
  canonical form; VPC firewall rules (:func:`fetch_firewall_rules`) as
  normalized action/direction/match records; and the presence-only network-tag
  vocabulary (:func:`fetch_network_tags`) — a USE-SITE view unioned from
  firewall rules and instance tags, since GCP has no "list all tags" API;
- the Compute-side POLICY surfaces: hierarchical firewall policies
  (:func:`fetch_firewall_policies`, a ``firewallPolicies`` list-then-get walk
  normalizing associations to hierarchy nodes and each rule to the estate
  schema — the ``goto_next`` delegation action survives verbatim) and Cloud
  Armor security policies (:func:`fetch_security_policies`);
- the VPC Service Controls surfaces via the Access Context Manager v1 API:
  service perimeters (:func:`fetch_perimeters`, keeping the enforced ``status``
  and the dry-run ``spec`` strictly separate), access levels
  (:func:`fetch_access_levels`) and the supported-service vocabulary
  (:func:`fetch_restricted_services`);
- the ESTATE half of Org Policy — the effective set-policies at named nodes
  (:func:`fetch_org_policies`), keyed ``<node>|<constraint>`` and complementary
  to the constraint-DEFINITION vocabulary :func:`fetch_constraints` enumerates;
- service-account emails via the IAM API (:func:`fetch_service_accounts`),
  stored BARE (no ``serviceAccount:`` prefix) so the category stays distinct
  from ``principals``.

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
import re
import subprocess
from collections import deque
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Iterator

from .core.log import fmt_cmd, get_logger
from .knowledge import GcpSnapshot

logger = get_logger(__name__)

__all__ = [
    "MissingDependencyError",
    "capture_snapshot",
    "default_client",
    "fetch_access_levels",
    "fetch_asset_types",
    "fetch_constraints",
    "fetch_firewall_policies",
    "fetch_firewall_rules",
    "fetch_hierarchy",
    "fetch_iam_bindings",
    "fetch_network_tags",
    "fetch_networks",
    "fetch_org_policies",
    "fetch_perimeters",
    "fetch_permissions",
    "fetch_principals",
    "fetch_principals_and_bindings",
    "fetch_resource_types",
    "fetch_restricted_services",
    "fetch_roles",
    "fetch_security_policies",
    "fetch_service_accounts",
    "fetch_subnetworks",
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
_API_VERSIONS = {"iam": "v1", "orgpolicy": "v2", "cloudasset": "v1", "compute": "v1",
                 "accesscontextmanager": "v1", "cloudresourcemanager": "v3"}


def default_client(api: str, version: str | None = None) -> Any:
    """Build a live discovery client for *api* ("iam" / "orgpolicy" /
    "cloudasset" / "compute" / "accesscontextmanager" /
    "cloudresourcemanager"), resolving the optional SDK only now — never at
    import.

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


def _paginate_aggregated(list_call: Callable[..., Any],
                         **params: Any) -> Iterator[dict[str, Any]]:
    """Yield the per-scope value objects across every ``nextPageToken`` page of a
    discovery-style ``aggregatedList`` method — whose ``items`` is a
    ``scope -> {<collection> | warning}`` map, not a flat list. Warning-only
    scopes carry no collection key, so callers that ``.get`` the collection skip
    them for free."""
    token: str | None = None
    while True:
        call_params = dict(params)
        if token:
            call_params["pageToken"] = token
        page = list_call(**call_params).execute() or {}
        yield from (page.get("items") or {}).values()
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

def _orgpolicy_node_collection(orgpolicy: Any, parent: str) -> Any:
    """The node-type accessor (``organizations`` / ``folders`` / ``projects``)
    for an org-policy *parent*, probed by prefix — the client exposes a distinct
    accessor per node type. Shared by the constraint-DEFINITION fetcher (which
    then reaches ``.constraints()``) and the effective set-policy fetcher (which
    reaches ``.policies()``), so neither hardcodes a single collection name."""
    for prefix, accessor in (("organizations/", "organizations"),
                             ("folders/", "folders"),
                             ("projects/", "projects")):
        if parent.startswith(prefix):
            return getattr(orgpolicy, accessor)()
    raise ValueError(f"org-policy parent {parent!r} must look like "
                     f"'organizations/<id>', 'folders/<id>' or 'projects/<id>'")


def _constraints_collection(orgpolicy: Any, parent: str) -> Any:
    return _orgpolicy_node_collection(orgpolicy, parent).constraints()


def _policies_collection(orgpolicy: Any, parent: str) -> Any:
    return _orgpolicy_node_collection(orgpolicy, parent).policies()


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

def _search_iam_policies(asset: Any, scope: str) -> Iterator[tuple[str | None, Mapping[str, Any]]]:
    """Yield ``(resource, policy)`` for every CAI ``searchAllIamPolicies`` result
    under *scope*, paginating the estate exactly ONCE. ``resource`` is the
    result's full resource name (None when a result omits it — it then cannot be
    keyed) and ``policy`` is its IAM policy object (``{}`` when absent). Every
    per-resource fetcher below reads this one iterator, so principals and
    bindings never trigger a second pagination of the same estate."""
    search = asset.v1().searchAllIamPolicies
    for result in _paginate(search, "results", scope=scope):
        yield result.get("resource"), (result.get("policy") or {})


def fetch_principals(asset: Any, scope: str) -> frozenset[str]:
    """Every principal bound anywhere in *scope* (a ``projects/``,
    ``folders/`` or ``organizations/`` name), via CAI
    ``searchAllIamPolicies`` — deduplicated binding members
    ("user:…", "serviceAccount:…", "group:…", …)."""
    principals: set[str] = set()
    for _resource, policy in _search_iam_policies(asset, scope):
        for binding in policy.get("bindings", ()):
            principals.update(m for m in binding.get("members", ()) if m)
    logger.debug("fetched %d distinct principals in %s", len(principals), scope)
    return frozenset(principals)


def _binding_record(binding: Mapping[str, Any]) -> dict[str, Any] | None:
    """One IAM binding → the ``iam_bindings`` binding shape (role / members /
    verbatim condition), or None when it carries no ``role`` — a member set with
    no role grants nothing, so it is dropped rather than keyed under a guess. The
    ``condition`` object is preserved exactly (or None), never flattened."""
    role = binding.get("role")
    if not role:
        return None
    return {
        "role": role,
        "members": [m for m in binding.get("members", ()) if m],
        "condition": binding.get("condition"),
    }


def fetch_iam_bindings(asset: Any, scope: str) -> dict[str, dict[str, Any]]:
    """The full IAM bindings under *scope*, via CAI ``searchAllIamPolicies``, as
    the ``iam_bindings`` estate schema: each resource mapped to a ``bindings``
    list of ``{role, members, condition}`` records with the ``condition`` object
    kept verbatim (or None). A binding with no ``role`` is skipped; a result with
    no resource name cannot be keyed and is skipped.

    Where :func:`fetch_principals` walks exactly this data and discards
    everything but the member strings, this keeps the roles and conditions a
    conditional-binding or escalation check needs."""
    bindings: dict[str, dict[str, Any]] = {}
    for resource, policy in _search_iam_policies(asset, scope):
        if not resource:
            continue
        records = [r for b in policy.get("bindings", ())
                   if (r := _binding_record(b)) is not None]
        bindings[resource] = {"bindings": records}
    logger.debug("fetched IAM bindings for %d resources in %s", len(bindings), scope)
    return bindings


def fetch_principals_and_bindings(
        asset: Any, scope: str) -> tuple[frozenset[str], dict[str, dict[str, Any]]]:
    """Both the principal set AND the full IAM bindings under *scope* from ONE
    pass over the CAI estate — the two categories share the single
    :func:`_search_iam_policies` pagination rather than walking it twice. The
    principal set is identical to what :func:`fetch_principals` returns (members
    from every binding, role or not); the bindings table is identical to
    :func:`fetch_iam_bindings`. Used by :func:`capture_snapshot` when both
    categories are requested."""
    principals: set[str] = set()
    bindings: dict[str, dict[str, Any]] = {}
    for resource, policy in _search_iam_policies(asset, scope):
        records: list[dict[str, Any]] = []
        for binding in policy.get("bindings", ()):
            principals.update(m for m in binding.get("members", ()) if m)
            record = _binding_record(binding)
            if record is not None:
                records.append(record)
        if resource:
            bindings[resource] = {"bindings": records}
    logger.debug("fetched %d principals and IAM bindings for %d resources in %s",
                 len(principals), len(bindings), scope)
    return frozenset(principals), bindings


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


# ── Compute Engine: networks, subnetworks, firewall rules, tags ───────────────

# A Compute self-link is a fully-qualified URL; strip this prefix to reach the
# resource-relative path the snapshot's canonical forms use.
_COMPUTE_LINK_PREFIX = "https://www.googleapis.com/compute/v1/"


def _normalize_compute_link(link: Any, kind: str) -> str | None:
    """A Compute ``selfLink`` (or bare ``network`` reference) → the snapshot's
    canonical ``projects/<p>/global/<kind>/<n>`` or
    ``projects/<p>/regions/<r>/<kind>/<n>`` form.

    Strips any ``https://www.googleapis.com/compute/v1/`` prefix, then verifies
    the ``/global/<kind>/`` or ``/regions/<r>/<kind>/`` shape. Anything else —
    a wrong kind, an unexpected scope, junk — logs and returns None, so a
    malformed link is dropped rather than smuggled in as a bogus name."""
    if not isinstance(link, str) or not link:
        logger.warning("compute %s reference is not a non-empty string (%r) — skipped",
                       kind, link)
        return None
    path = link[len(_COMPUTE_LINK_PREFIX):] if link.startswith(_COMPUTE_LINK_PREFIX) else link
    k = re.escape(kind)
    if re.fullmatch(rf"projects/[^/]+/global/{k}/[^/]+", path) or \
            re.fullmatch(rf"projects/[^/]+/regions/[^/]+/{k}/[^/]+", path):
        return path
    logger.warning("compute %s reference %r is not a global/regional %s link — skipped",
                   kind, link, kind)
    return None


def fetch_networks(compute: Any, project: str) -> frozenset[str]:
    """Every VPC network in *project*, via Compute ``networks.list``, as
    canonical ``projects/<p>/global/networks/<n>`` names (self-links
    normalized; a malformed link is logged and skipped, never guessed)."""
    networks: set[str] = set()
    for entry in _paginate(compute.networks().list, "items", project=project):
        name = _normalize_compute_link(entry.get("selfLink"), "networks")
        if name is not None:
            networks.add(name)
    logger.debug("fetched %d networks in %s", len(networks), project)
    return frozenset(networks)


def fetch_subnetworks(compute: Any, project: str) -> frozenset[str]:
    """Every subnetwork in *project*, via Compute ``subnetworks.aggregatedList``,
    as canonical ``projects/<p>/regions/<r>/subnetworks/<n>`` names.

    The aggregated response is keyed by scope; a scope carrying only a
    ``warning`` (no ``subnetworks``) is skipped, and each self-link is
    normalized (malformed links logged and dropped)."""
    subnetworks: set[str] = set()
    for scope in _paginate_aggregated(compute.subnetworks().aggregatedList,
                                      project=project):
        for entry in scope.get("subnetworks", ()):
            name = _normalize_compute_link(entry.get("selfLink"), "subnetworks")
            if name is not None:
                subnetworks.add(name)
    logger.debug("fetched %d subnetworks in %s", len(subnetworks), project)
    return frozenset(subnetworks)


def fetch_firewall_rules(compute: Any, project: str) -> dict[str, dict[str, Any]]:
    """VPC firewall rules in *project*, via Compute ``firewalls.list``, as
    snapshot-ready records keyed ``projects/<p>/global/firewalls/<name>``.

    Each record carries the normalized firewall-rule schema:
    network/direction/action/priority/disabled plus the range, tag,
    service-account and layer4 match sets. ``allowed`` maps to action
    ``allow``, ``denied`` to ``deny``; a rule carrying BOTH (impossible in a
    real API response) or NEITHER is skipped with a warning rather than
    guessed at. A rule whose network self-link will not normalize is likewise
    skipped, so every emitted record loads through ``GcpSnapshot.from_dict``."""
    rules: dict[str, dict[str, Any]] = {}
    for entry in _paginate(compute.firewalls().list, "items", project=project):
        name = entry.get("name")
        if not name:
            logger.warning("firewalls.list returned an entry with no name — skipped")
            continue
        has_allow, has_deny = "allowed" in entry, "denied" in entry
        if has_allow and has_deny:
            logger.warning("firewall rule %s carries both 'allowed' and 'denied' "
                           "(impossible) — skipped rather than guessed at", name)
            continue
        if has_allow:
            action, specs = "allow", entry.get("allowed") or ()
        elif has_deny:
            action, specs = "deny", entry.get("denied") or ()
        else:
            logger.warning("firewall rule %s carries neither 'allowed' nor 'denied' "
                           "— skipped", name)
            continue
        network = _normalize_compute_link(entry.get("network"), "networks")
        if network is None:
            logger.warning("firewall rule %s has an unusable network reference — "
                           "skipped", name)
            continue
        layer4: list[dict[str, Any]] = []
        for spec in specs:
            entry_l4: dict[str, Any] = {"protocol": spec.get("IPProtocol")}
            ports = spec.get("ports")
            if ports:
                entry_l4["ports"] = list(ports)
            layer4.append(entry_l4)
        record: dict[str, Any] = {
            "network": network,
            "direction": entry.get("direction", "INGRESS"),
            "action": action,
            "priority": entry.get("priority", 1000),
            "disabled": entry.get("disabled", False),
            "source_ranges": list(entry.get("sourceRanges") or ()),
            "destination_ranges": list(entry.get("destinationRanges") or ()),
            "source_tags": list(entry.get("sourceTags") or ()),
            "target_tags": list(entry.get("targetTags") or ()),
            "source_service_accounts": list(entry.get("sourceServiceAccounts") or ()),
            "target_service_accounts": list(entry.get("targetServiceAccounts") or ()),
            "layer4": layer4,
        }
        rules[f"projects/{project}/global/firewalls/{name}"] = record
    logger.debug("fetched %d firewall rules in %s", len(rules), project)
    return rules


def fetch_network_tags(compute: Any, project: str, *,
                       firewall_rules: dict[str, dict[str, Any]] | None = None
                       ) -> frozenset[str]:
    """The USE-SITE network-tag vocabulary for *project*: the union of every
    ``target_tags``/``source_tags`` across the firewall rules and every
    ``tags.items`` on an instance (via ``instances.aggregatedList``).

    This is deliberately NOT an authoritative registry — GCP exposes no "list
    all network tags" API. A tag exists only implicitly, created by the rule or
    instance naming it, so this category can prove a tag is IN USE but its
    False answers mean only "no captured resource currently uses this tag",
    never "this tag cannot exist". When *firewall_rules* is passed (already
    fetched by the caller) it is reused, avoiding a second ``firewalls.list``
    pagination."""
    if firewall_rules is None:
        firewall_rules = fetch_firewall_rules(compute, project)
    tags: set[str] = set()
    for record in firewall_rules.values():
        tags.update(record.get("target_tags") or ())
        tags.update(record.get("source_tags") or ())
    for scope in _paginate_aggregated(compute.instances().aggregatedList,
                                      project=project):
        for instance in scope.get("instances", ()):
            tags.update((instance.get("tags") or {}).get("items") or ())
    tags = {t for t in tags if t}
    logger.debug("fetched %d network tags in use in %s", len(tags), project)
    return frozenset(tags)


def fetch_service_accounts(iam: Any, project: str) -> frozenset[str]:
    """Every service account in *project*, via IAM
    ``projects.serviceAccounts.list``, as BARE emails
    (``ci-deployer@acme-prod.iam.gserviceaccount.com``) — no
    ``serviceAccount:`` prefix, matching this category's canonical form and
    keeping it distinct from ``principals``."""
    accounts: set[str] = set()
    collection = iam.projects().serviceAccounts()
    for entry in _paginate(collection.list, "accounts", name=f"projects/{project}"):
        email = entry.get("email")
        if email:
            accounts.add(email)
    logger.debug("fetched %d service accounts in %s", len(accounts), project)
    return frozenset(accounts)


# ── policy surfaces: hierarchical firewall, Cloud Armor, VPC-SC, org policy ───

# Resource-hierarchy node prefixes an "organizations/1"-style reference uses.
_HIERARCHY_NODE_TYPES = ("organizations", "folders", "projects")


def _str_list(value: Any) -> list[str]:
    """A JSON string array → a list of its non-empty strings, order kept;
    anything else → an empty list. Conservative: a non-string entry is dropped,
    never coerced — the estate schema's list fields are order-semantic strings."""
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _normalize_hierarchy_node(value: Any) -> str | None:
    """A hierarchy reference → its ``organizations/<id>`` / ``folders/<id>`` /
    ``projects/<id>`` node, or None. Tolerates a full firewall-policy path and a
    resource-manager URL (``//cloudresourcemanager.googleapis.com/folders/2``)
    by scanning for the first ``<type>/<id>`` pair, so an attachment target in
    any of GCP's spellings normalizes to the same node name a hierarchy check
    keys on."""
    if not isinstance(value, str) or not value:
        return None
    parts = value.split("/")
    for i in range(len(parts) - 1):
        if parts[i] in _HIERARCHY_NODE_TYPES and parts[i + 1]:
            return f"{parts[i]}/{parts[i + 1]}"
    return None


def _firewall_policy_full_name(policy: Mapping[str, Any]) -> str | None:
    """The policy's full hierarchical name
    ``organizations/<id>/locations/global/firewallPolicies/<pid>``. Uses the
    ``name`` verbatim when it is already a full path; otherwise composes it from
    the owning ``parent`` node and the human ``shortName`` (falling back to
    ``name``). None when neither yields a resolvable name — the policy is then
    dropped rather than keyed under a guess."""
    name = policy.get("name")
    if isinstance(name, str) and "/locations/global/firewallPolicies/" in name:
        return name
    node = _normalize_hierarchy_node(policy.get("parent"))
    short = policy.get("shortName") or name
    if node is None or not isinstance(short, str) or not short:
        return None
    return f"{node}/locations/global/firewallPolicies/{short}"


def _normalize_policy_rule(rule: Mapping[str, Any]) -> dict[str, Any]:
    """One REST hierarchical-firewall-policy rule → the estate ``rules[]`` shape:
    priority / action / direction / disabled, a snake_cased ``match`` block
    (src_ip_ranges / dest_ip_ranges / layer4) and the target sets. ``action`` is
    copied verbatim, so the ``goto_next`` delegation action — the whole point of
    a cross-level check — survives untouched."""
    match = rule.get("match")
    match_present = isinstance(match, Mapping)
    src = _str_list(match.get("srcIpRanges")) if match_present else []
    dest = _str_list(match.get("destIpRanges")) if match_present else []
    layer4 = [{"protocol": cfg.get("ipProtocol"), "ports": _str_list(cfg.get("ports"))}
              for cfg in ((match.get("layer4Configs") if match_present else None) or ())
              if isinstance(cfg, Mapping)]
    secure_tags = [tag.get("name") for tag in rule.get("targetSecureTags") or ()
                   if isinstance(tag, Mapping) and isinstance(tag.get("name"), str)]
    return {
        "priority": rule.get("priority"),
        "action": rule.get("action"),
        "direction": rule.get("direction"),
        "disabled": rule.get("disabled", False),
        "match": {"src_ip_ranges": src, "dest_ip_ranges": dest, "layer4": layer4},
        "target_resources": _str_list(rule.get("targetResources")),
        "target_service_accounts": _str_list(rule.get("targetServiceAccounts")),
        "target_secure_tags": secure_tags,
    }


def fetch_firewall_policies(compute: Any, parent: str) -> dict[str, dict[str, Any]]:
    """Hierarchical firewall policies under *parent* (a numeric org/folder id),
    via a two-step Compute walk: ``firewallPolicies.list(parentId=...)`` to
    enumerate, then one ``firewallPolicies.get(firewallPolicy=<id>)`` per policy
    to obtain its ``rules`` and ``associations``.

    Records use the ``hierarchical_firewall_policies`` estate schema, keyed on
    the policy's full name: ``attachments`` normalizes each association's
    ``attachmentTarget`` to an ``organizations/<id>`` / ``folders/<id>`` node,
    and each rule normalizes to the estate rule shape (``goto_next`` preserved).
    A policy whose full name will not resolve is logged and skipped."""
    policies: dict[str, dict[str, Any]] = {}
    collection = compute.firewallPolicies()
    for summary in _paginate(collection.list, "items", parentId=parent):
        pid = summary.get("name")
        if not pid:
            logger.warning("firewallPolicies.list (parentId=%r) returned an entry "
                           "with no name — skipped", parent)
            continue
        policy = collection.get(firewallPolicy=pid).execute() or {}
        key = _firewall_policy_full_name(policy)
        if key is None:
            logger.warning("firewall policy %r under %r has no resolvable full "
                           "name — skipped", pid, parent)
            continue
        attachments: list[str] = []
        for assoc in policy.get("associations") or ():
            if not isinstance(assoc, Mapping):
                continue
            node = _normalize_hierarchy_node(assoc.get("attachmentTarget"))
            if node is not None and node not in attachments:
                attachments.append(node)
        rules = [_normalize_policy_rule(rule) for rule in policy.get("rules") or ()
                 if isinstance(rule, Mapping)]
        policies[key] = {"attachments": attachments, "rules": rules}
    logger.debug("fetched %d firewall policies under parentId=%s", len(policies), parent)
    return policies


def _normalize_armor_rule(rule: Mapping[str, Any]) -> dict[str, Any]:
    """One Cloud Armor rule → the estate ``rules[]`` shape: priority / action /
    preview and a ``match`` block carrying ``src_ip_ranges`` (from
    ``match.config.srcIpRanges``), ``versioned_expr`` (from
    ``match.versionedExpr``) and ``expr`` (the CEL string from
    ``match.expr.expression``, or None)."""
    match = rule.get("match") if isinstance(rule.get("match"), Mapping) else {}
    config = match.get("config") if isinstance(match.get("config"), Mapping) else {}
    expr = match.get("expr") if isinstance(match.get("expr"), Mapping) else {}
    return {
        "priority": rule.get("priority"),
        "action": rule.get("action"),
        "preview": rule.get("preview", False),
        "match": {
            "src_ip_ranges": _str_list(config.get("srcIpRanges")),
            "versioned_expr": match.get("versionedExpr"),
            "expr": expr.get("expression"),
        },
    }


def fetch_security_policies(compute: Any, project: str) -> dict[str, dict[str, Any]]:
    """Cloud Armor security policies in *project*, via Compute
    ``securityPolicies.list``, keyed ``projects/<p>/global/securityPolicies/
    <name>``. Records use the ``cloud_armor_policies`` estate schema: the policy
    ``type`` plus each rule normalized by :func:`_normalize_armor_rule` — the
    priority-``2147483647`` default rule included, since a check reasoning about
    fall-through coverage must see it."""
    policies: dict[str, dict[str, Any]] = {}
    for entry in _paginate(compute.securityPolicies().list, "items", project=project):
        name = entry.get("name")
        if not name:
            logger.warning("securityPolicies.list in %s returned an entry with no "
                           "name — skipped", project)
            continue
        rules = [_normalize_armor_rule(rule) for rule in entry.get("rules") or ()
                 if isinstance(rule, Mapping)]
        policies[f"projects/{project}/global/securityPolicies/{name}"] = {
            "type": entry.get("type"),
            "rules": rules,
        }
    logger.debug("fetched %d Cloud Armor policies in %s", len(policies), project)
    return policies


# The VPC-SC perimeter config-block fields, camelCase → the snake_case names the
# vpc_sc_perimeters estate schema uses. status (enforced) and spec (dry-run) each
# carry a block of this shape; they are normalized independently and never merged.
_PERIMETER_CONFIG_FIELDS = {
    "resources": "resources",
    "accessLevels": "access_levels",
    "restrictedServices": "restricted_services",
    "vpcAccessibleServices": "vpc_accessible_services",
    "ingressPolicies": "ingress_policies",
    "egressPolicies": "egress_policies",
}


def _normalize_perimeter_config(block: Any) -> dict[str, Any] | None:
    """A perimeter ``status``/``spec`` config block → its snake_cased form, or
    None when the block is absent (a perimeter with no dry-run ``spec`` keeps a
    null spec — a missing dry-run config is not an empty enforced one)."""
    if not isinstance(block, Mapping):
        return None
    out: dict[str, Any] = {}
    for camel, snake in _PERIMETER_CONFIG_FIELDS.items():
        if camel in block:
            out[snake] = block[camel]
    return out


def fetch_perimeters(acm: Any, access_policy: str) -> dict[str, dict[str, Any]]:
    """VPC-SC service perimeters under *access_policy* (an
    ``accessPolicies/<n>`` name), via Access Context Manager
    ``accessPolicies.servicePerimeters.list``. Records use the
    ``vpc_sc_perimeters`` estate schema keyed on the perimeter's full name, with
    the enforced ``status`` and the dry-run ``spec`` kept STRICTLY separate —
    never merged, because a dry-run spec is a proposal, not enforcement — and
    ``useExplicitDryRunSpec`` normalized to ``use_explicit_dry_run_spec``."""
    perimeters: dict[str, dict[str, Any]] = {}
    collection = acm.accessPolicies().servicePerimeters()
    for entry in _paginate(collection.list, "servicePerimeters", parent=access_policy):
        name = entry.get("name")
        if not name:
            logger.warning("servicePerimeters.list under %s returned an entry with "
                           "no name — skipped", access_policy)
            continue
        perimeters[name] = {
            "perimeter_type": entry.get("perimeterType"),
            "use_explicit_dry_run_spec": entry.get("useExplicitDryRunSpec", False),
            "status": _normalize_perimeter_config(entry.get("status")),
            "spec": _normalize_perimeter_config(entry.get("spec")),
        }
    logger.debug("fetched %d perimeters under %s", len(perimeters), access_policy)
    return perimeters


def fetch_access_levels(acm: Any, access_policy: str) -> frozenset[str]:
    """Every access level under *access_policy*, via Access Context Manager
    ``accessPolicies.accessLevels.list``, stored as full
    ``accessPolicies/<n>/accessLevels/<name>`` names."""
    levels: set[str] = set()
    collection = acm.accessPolicies().accessLevels()
    for entry in _paginate(collection.list, "accessLevels", parent=access_policy):
        name = entry.get("name")
        if name:
            levels.add(name)
    logger.debug("fetched %d access levels under %s", len(levels), access_policy)
    return frozenset(levels)


def fetch_restricted_services(acm: Any) -> frozenset[str]:
    """The VPC-SC supported-service vocabulary, via Access Context Manager
    ``services.list`` — each entry's ``name``, a service hostname such as
    ``storage.googleapis.com``.

    This is the set of services VPC Service Controls CAN restrict, NOT the set a
    given perimeter DOES restrict (that lives per-perimeter in
    ``status.restricted_services``); it is the enumeration a check consults to
    tell a real supported service from a typo."""
    services: set[str] = set()
    for entry in _paginate(acm.services().list, "services"):
        name = entry.get("name")
        if name:
            services.add(name)
    logger.debug("fetched %d supported (restrictable) services", len(services))
    return frozenset(services)


def _org_policy_constraint(name: Any) -> str | None:
    """The canonical ``constraints/<id>`` name from an org-policy resource
    ``name`` (``projects/123/policies/compute.requireShieldedVm`` → its trailing
    ``policies/<id>`` segment, re-prefixed). None when the name carries no such
    segment — the policy is then skipped rather than keyed under a guess."""
    if not isinstance(name, str) or "/policies/" not in name:
        return None
    tail = name.rsplit("/policies/", 1)[1]
    if not tail:
        return None
    return f"constraints/{tail}"


def _normalize_org_policy_rules(spec: Mapping[str, Any]) -> list[dict[str, Any]]:
    """A ``spec.rules[]`` array → the estate ``rules[]`` shape: ``enforce``,
    ``allow_all`` (from ``allowAll``), ``deny_all`` (from ``denyAll``),
    ``allowed_values``/``denied_values`` (from ``values.allowedValues`` /
    ``values.deniedValues``) and ``condition`` (from ``condition.expression``)."""
    rules: list[dict[str, Any]] = []
    for rule in spec.get("rules") or ():
        if not isinstance(rule, Mapping):
            continue
        values = rule.get("values") if isinstance(rule.get("values"), Mapping) else {}
        condition = rule.get("condition") if isinstance(rule.get("condition"), Mapping) else {}
        rules.append({
            "enforce": rule.get("enforce"),
            "allow_all": rule.get("allowAll"),
            "deny_all": rule.get("denyAll"),
            "allowed_values": _str_list(values.get("allowedValues")),
            "denied_values": _str_list(values.get("deniedValues")),
            "condition": condition.get("expression"),
        })
    return rules


def fetch_org_policies(orgpolicy: Any,
                       nodes: Iterable[str]) -> dict[str, dict[str, Any]]:
    """The effective org-policy SET-policies at each node in *nodes* (each an
    ``organizations/<id>``, ``folders/<id>`` or ``projects/<id>`` name), via the
    v2 ``policies.list(parent=node)`` under the node-type accessor probed by
    :func:`_orgpolicy_node_collection`.

    Records use the ``org_policies`` estate schema, keyed on the composite
    ``<node>|<constraint>``: ``spec.rules[]`` maps to ``rules`` and
    ``spec.reset`` / ``spec.inheritFromParent`` to the top-level ``reset`` /
    ``inherit_from_parent``. This is the ESTATE half of Org Policy — what
    :mod:`~gcp_grounding.org_checks` compares against — and is INDEPENDENT of the
    constraint-DEFINITION vocabulary :func:`fetch_constraints` enumerates.

    A policy whose name yields no constraint id is skipped with a warning; a
    duplicate composite key across nodes raises rather than silently
    overwriting, so a merge can never blend two nodes' set-policies."""
    nodes = tuple(nodes)
    policies: dict[str, dict[str, Any]] = {}
    for node in nodes:
        collection = _policies_collection(orgpolicy, node)
        for entry in _paginate(collection.list, "policies", parent=node):
            constraint = _org_policy_constraint(entry.get("name"))
            if constraint is None:
                logger.warning("org policy %r under %s yields no constraint id — "
                               "skipped", entry.get("name"), node)
                continue
            key = f"{node}|{constraint}"
            if key in policies:
                raise ValueError(
                    f"org policy {key!r} appears more than once across the "
                    f"requested nodes — refusing to overwrite one node's "
                    f"set-policy with another's")
            spec = entry.get("spec") if isinstance(entry.get("spec"), Mapping) else {}
            policies[key] = {
                "node": node,
                "constraint": constraint,
                "reset": bool(spec.get("reset", False)),
                "inherit_from_parent": bool(spec.get("inheritFromParent", False)),
                "rules": _normalize_org_policy_rules(spec),
            }
    logger.debug("fetched %d org set-policies across %d node(s)",
                 len(policies), len(nodes))
    return policies


# ── Cloud Resource Manager: the resource hierarchy ────────────────────────────

def _hierarchy_root_type(root: str) -> str:
    """The ``resource_hierarchy`` node type for a walk *root*, or a ValueError.
    A walk starts at an ``organizations/<id>`` or a ``folders/<id>`` — nothing
    else has children to enumerate."""
    if root.startswith("organizations/"):
        return "organization"
    if root.startswith("folders/"):
        return "folder"
    raise ValueError(f"hierarchy root {root!r} must look like 'organizations/<id>' "
                     f"or 'folders/<id>' — a walk starts at an org or a folder")


def _hierarchy_number(name: Any) -> str | None:
    """The trailing numeric id of a ``<type>/<id>`` resource name (a project's
    ``projects/<number>`` name, a folder's ``folders/<id>``, an org's
    ``organizations/<id>``), or None. This is what feeds the ``projects/<number>``
    alias :meth:`GcpSnapshot.hierarchy_names` builds."""
    if isinstance(name, str) and "/" in name:
        ident = name.rsplit("/", 1)[1]
        return ident or None
    return None


def _list_hierarchy_children(list_call: Callable[..., Any], item_key: str,
                             node: str) -> tuple[list[dict[str, Any]], bool]:
    """Fully paginate *item_key* children of *node*, returning ``(items, ok)``.
    ``ok`` is False when a page errored — the whole subtree under *node* is then
    dropped and the caller marks the walk truncated, because a hierarchy that
    silently omits a subtree but is presented as captured would prove false
    ABSENCE for every node it dropped."""
    try:
        return list(_paginate(list_call, item_key, parent=node)), True
    except Exception as exc:  # noqa: BLE001 — any list/page failure drops the subtree
        logger.warning("listing %s under %s failed (%s) — subtree dropped; the "
                       "hierarchy walk is truncated", item_key, node, exc)
        return [], False


def fetch_hierarchy(crm: Any, root: str, *,
                    max_depth: int = 16) -> tuple[dict[str, dict[str, Any]], bool]:
    """Breadth-first walk of the resource hierarchy from *root* (an
    ``organizations/<id>`` or ``folders/<id>``), via Cloud Resource Manager v3
    ``folders.list(parent=...)`` and ``projects.list(parent=...)`` (both
    paginated), into the ``resource_hierarchy`` schema.

    Returns ``(hierarchy, truncated)``. Each record carries ``parent`` / ``type``
    / ``number`` / ``display_name``; keys are canonical (``organizations/<id>``,
    ``folders/<id>``, ``projects/<projectId>``), and a project's ``number`` comes
    from its ``name`` (``projects/<number>``) so
    :meth:`GcpSnapshot.hierarchy_names` can build the ``projects/<number>`` alias.
    The *root* node itself is included with a null parent; projects are leaves.

    ``truncated`` is True when the walk stopped early — on *max_depth* (a visited
    set plus the depth bound guard against a cycle or pathological nesting), on a
    parent link that closed a cycle back onto an already-recorded node, or on any
    per-page error that dropped a subtree.

    A TRUNCATED WALK MUST NOT BE PRESENTED AS A CAPTURED HIERARCHY: a partial
    hierarchy marked captured is WORSE than none, because
    :meth:`GcpSnapshot.hierarchy_names` would then prove ABSENCE for every
    out-of-scope node and turn ordinary VPC-SC and hierarchical-firewall
    references into false ``ungrounded`` blocks. Uncaptured means every dependent
    check abstains and says why; truncated-but-captured means it blocks and is
    wrong — the same reasoning that makes ``network_tags`` presence-only, applied
    to a table. :func:`capture_snapshot` therefore refuses to set the category
    when this flag is True; a caller who genuinely wants the partial walk calls
    this function directly and sets the field itself.
    """
    node_type = _hierarchy_root_type(root)
    hierarchy: dict[str, dict[str, Any]] = {
        root: {"parent": None, "type": node_type,
               "number": _hierarchy_number(root), "display_name": None},
    }
    truncated = False
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(root, 0)])
    while queue:
        node, depth = queue.popleft()
        if node in visited:
            continue
        visited.add(node)
        if depth >= max_depth:
            logger.warning("hierarchy walk from %s reached max_depth=%d at %s — "
                           "stopping; result is truncated", root, max_depth, node)
            truncated = True
            continue
        folders, ok = _list_hierarchy_children(crm.folders().list, "folders", node)
        truncated = truncated or not ok
        for folder in folders:
            fname = folder.get("name")
            if not isinstance(fname, str) or not fname:
                logger.warning("folders.list under %s returned an entry with no "
                               "name — skipped", node)
                continue
            if fname in hierarchy:
                logger.warning("hierarchy walk from %s revisited %s (cycle) — "
                               "not re-expanded; result is truncated", root, fname)
                truncated = True
                continue
            hierarchy[fname] = {
                "parent": folder.get("parent") or node,
                "type": "folder",
                "number": _hierarchy_number(fname),
                "display_name": folder.get("displayName"),
            }
            queue.append((fname, depth + 1))
        projects, ok = _list_hierarchy_children(crm.projects().list, "projects", node)
        truncated = truncated or not ok
        for project in projects:
            pid = project.get("projectId")
            if not isinstance(pid, str) or not pid:
                logger.warning("projects.list under %s returned an entry with no "
                               "projectId — skipped", node)
                continue
            key = f"projects/{pid}"
            if key in hierarchy:
                logger.warning("hierarchy walk from %s revisited %s (cycle) — "
                               "skipped; result is truncated", root, key)
                truncated = True
                continue
            hierarchy[key] = {
                "parent": project.get("parent") or node,
                "type": "project",
                "number": _hierarchy_number(project.get("name")),
                "display_name": project.get("displayName"),
            }
    logger.debug("hierarchy walk from %s captured %d nodes (truncated=%s)",
                 root, len(hierarchy), truncated)
    return hierarchy, truncated


# ── capture orchestration ─────────────────────────────────────────────────────

def write_snapshot(snapshot: GcpSnapshot, path: str | os.PathLike[str]) -> None:
    """Serialize *snapshot* to *path* deterministically (sorted keys, so
    successive captures diff cleanly)."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True) + "\n")
    logger.debug("wrote snapshot to %s (captured_at=%s)", path, snapshot.captured_at)


def capture_snapshot(*, iam: Any = None, orgpolicy: Any = None, asset: Any = None,
                     compute: Any = None, acm: Any = None, crm: Any = None,
                     custom_role_parents: Iterable[str] = (),
                     permission_resources: Iterable[str] = (),
                     service_account_projects: Iterable[str] = (),
                     orgpolicy_parent: str | None = None,
                     org_policy_nodes: Iterable[str] = (),
                     asset_scope: str | None = None,
                     capture_iam_bindings: bool = False,
                     compute_project: str | None = None,
                     firewall_policy_parents: Iterable[str] = (),
                     access_policy: str | None = None,
                     hierarchy_root: str | None = None,
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

    The policy-surface categories ride their own opt-ins: *acm* (with
    *access_policy*) captures ``vpc_sc_perimeters`` / ``access_levels`` /
    ``restricted_services``; *firewall_policy_parents* captures the Compute-side
    policy surfaces ``hierarchical_firewall_policies`` (merged across the
    parents, raising on a duplicate key) and ``cloud_armor_policies`` (from
    *compute_project*); *org_policy_nodes* captures ``org_policies``. The
    effective-set-policy capture *org_policy_nodes* is INDEPENDENT of
    *orgpolicy_parent*, which drives the constraint-DEFINITION vocabulary — the
    two are complementary and a caller may want either alone.

    ``resource_types`` comes from the terraform schema alone and is marked
    captured only when that schema was actually requested: it is the
    terraform provider vocabulary, and unioning CAI asset types into it
    would flag the category as enumerated with the wrong namespace — a
    partial capture manufacturing false "ungrounded" evidence.

    *capture_iam_bindings* (which needs *asset*) additionally captures the full
    ``iam_bindings`` table from the SAME pass that captures ``principals`` — one
    CAI pagination, both categories. *crm* (with *hierarchy_root*) captures
    ``resource_hierarchy`` via :func:`fetch_hierarchy`, but ONLY when that walk
    did not truncate: a truncated walk leaves the category ``None`` (a warning
    names the root) rather than manufacturing false "ungrounded" verdicts for
    every node outside the walk — see :func:`fetch_hierarchy`.
    """
    custom_role_parents = tuple(custom_role_parents)
    permission_resources = tuple(permission_resources)
    service_account_projects = tuple(service_account_projects)
    firewall_policy_parents = tuple(firewall_policy_parents)
    org_policy_nodes = tuple(org_policy_nodes)
    if (custom_role_parents or permission_resources
            or service_account_projects) and iam is None:
        raise ValueError("custom_role_parents/permission_resources/"
                         "service_account_projects given but no iam client to "
                         "fetch them with")
    # Org Policy has two independent halves off one client: the constraint
    # DEFINITION vocabulary (orgpolicy_parent) and the effective SET-policies
    # (org_policy_nodes). Either alone is valid; a client with neither, or a
    # parent/nodes with no client, is the half-configured error.
    if orgpolicy_parent is not None and orgpolicy is None:
        raise ValueError("org-policy constraint capture needs both an orgpolicy "
                         "client and an orgpolicy_parent")
    if org_policy_nodes and orgpolicy is None:
        raise ValueError("org-policy estate capture needs an orgpolicy client")
    if orgpolicy is not None and orgpolicy_parent is None and not org_policy_nodes:
        raise ValueError("an orgpolicy client needs an orgpolicy_parent (constraint "
                         "definitions) and/or org_policy_nodes (effective "
                         "set-policies) to fetch")
    if (asset is None) != (asset_scope is None):
        raise ValueError("principal capture needs both a Cloud Asset Inventory "
                         "client and an asset_scope")
    if capture_iam_bindings and asset is None:
        raise ValueError("capture_iam_bindings needs a Cloud Asset Inventory "
                         "client (asset) — IAM bindings come from the same CAI "
                         "searchAllIamPolicies pass as principals")
    if (crm is None) != (hierarchy_root is None):
        raise ValueError("resource-hierarchy capture needs both a Cloud Resource "
                         "Manager client (crm) and a hierarchy_root")
    if (compute is None) != (compute_project is None):
        raise ValueError("compute capture needs both a compute client and a "
                         "compute_project")
    if firewall_policy_parents and compute is None:
        raise ValueError("hierarchical firewall policy capture needs a compute "
                         "client (firewall_policy_parents given without one)")
    if (acm is None) != (access_policy is None):
        raise ValueError("VPC Service Controls capture needs both an acm (Access "
                         "Context Manager) client and an access_policy")

    data: dict[str, Any] = {"captured_at": captured_at or fresh_captured_at()}
    if iam is not None:
        data["roles"] = fetch_roles(iam, custom_role_parents=custom_role_parents)
        if permission_resources:
            data["permissions"] = sorted(fetch_permissions(iam, permission_resources))
        if service_account_projects:
            accounts: set[str] = set()
            for sa_project in service_account_projects:
                accounts.update(fetch_service_accounts(iam, sa_project))
            data["service_accounts"] = sorted(accounts)
    if orgpolicy_parent is not None:
        data["constraints"] = fetch_constraints(orgpolicy, orgpolicy_parent)
    if org_policy_nodes:
        data["org_policies"] = fetch_org_policies(orgpolicy, org_policy_nodes)
    if asset is not None:
        if capture_iam_bindings:
            # One CAI pass populates BOTH categories rather than paginating twice.
            principals, iam_bindings = fetch_principals_and_bindings(asset, asset_scope)
            data["principals"] = sorted(principals)
            data["iam_bindings"] = iam_bindings
        else:
            data["principals"] = sorted(fetch_principals(asset, asset_scope))
    if crm is not None:
        hierarchy, truncated = fetch_hierarchy(crm, hierarchy_root)
        if truncated:
            # A partial hierarchy marked captured is worse than none: it would
            # prove ABSENCE for every node outside the walk. Leave it uncaptured.
            logger.warning("resource-hierarchy walk from %s truncated (max_depth, "
                           "a cycle, or a per-page error) — leaving "
                           "resource_hierarchy UNCAPTURED so dependent checks "
                           "abstain rather than fabricate false 'ungrounded' "
                           "verdicts", hierarchy_root)
        else:
            data["resource_hierarchy"] = hierarchy
    if compute is not None:
        firewall_rules = fetch_firewall_rules(compute, compute_project)
        data["firewall_rules"] = firewall_rules
        data["networks"] = sorted(fetch_networks(compute, compute_project))
        data["subnetworks"] = sorted(fetch_subnetworks(compute, compute_project))
        # Reuse the firewall dict so tags cost no second firewalls.list walk.
        data["network_tags"] = sorted(fetch_network_tags(
            compute, compute_project, firewall_rules=firewall_rules))
    if firewall_policy_parents:
        # The Compute-side POLICY surfaces are one opt-in: hierarchical firewall
        # policies (org/folder-scoped, merged across parents) and — additionally,
        # since it is likewise sourced from the compute client — Cloud Armor for
        # compute_project. Kept off the bare-compute path above so a networks-only
        # capture stays exactly the four network categories.
        hfw: dict[str, dict[str, Any]] = {}
        for fp_parent in firewall_policy_parents:
            for key, record in fetch_firewall_policies(compute, fp_parent).items():
                if key in hfw:
                    raise ValueError(
                        f"hierarchical firewall policy {key!r} appears under more "
                        f"than one of firewall_policy_parents — refusing to "
                        f"overwrite one parent's policy with another's")
                hfw[key] = record
        data["hierarchical_firewall_policies"] = hfw
        data["cloud_armor_policies"] = fetch_security_policies(compute, compute_project)
    if acm is not None:
        data["vpc_sc_perimeters"] = fetch_perimeters(acm, access_policy)
        data["access_levels"] = sorted(fetch_access_levels(acm, access_policy))
        data["restricted_services"] = sorted(fetch_restricted_services(acm))
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
