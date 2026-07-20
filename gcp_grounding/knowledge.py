"""Offline knowledge base: a frozen snapshot of the GCP estate.

A :class:`GcpSnapshot` is the sole source of truth for every existence
question the reasoner asks — roles, permissions, principals, org-policy
constraints, resource types. It is loaded from a committed JSON file
(``fetch.py`` populates one from live APIs, elsewhere); this module does no
network I/O and imports no GCP SDKs, so grounding runs offline,
deterministically, with no credentials.

The one semantic that matters — **unknown vs absent**:

- A category the snapshot *never enumerated* (key missing from the JSON,
  e.g. principals when Cloud Asset Inventory was not captured) answers every
  lookup with the :data:`UNKNOWN` sentinel, so the reasoner emits an honest
  ``unverified`` verdict.
- A category that *was* enumerated (present, even as an empty list) answers
  ``False``/``None`` for names it does not contain — evidence for an
  ``ungrounded`` verdict.

:data:`UNKNOWN` deliberately refuses truthiness (``bool(UNKNOWN)`` raises)
so a naive ``if not snapshot.role_exists(r)`` cannot silently turn "not
captured" into a false ``ungrounded``; compare with ``is UNKNOWN`` /
``is True`` / ``is False``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Mapping

from .core.log import get_logger

logger = get_logger(__name__)

__all__ = ["UNKNOWN", "Unknown", "GcpSnapshot"]


class Unknown:
    """Type of the :data:`UNKNOWN` sentinel — the snapshot never enumerated
    the category this lookup belongs to, so existence is undecidable here.

    Do not instantiate; ``Unknown()`` always returns the singleton.
    """

    _instance: "Unknown | None" = None

    def __new__(cls) -> "Unknown":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNKNOWN"

    def __bool__(self) -> bool:
        raise TypeError(
            "UNKNOWN is neither True nor False — this category was not captured "
            "in the snapshot; compare with `is UNKNOWN` and emit an 'unverified' "
            "verdict, never 'ungrounded'"
        )


UNKNOWN = Unknown()

# Every top-level key a snapshot may carry besides captured_at. A typo here
# ("role" for "roles") must not silently demote a whole category to UNKNOWN,
# so from_dict rejects unrecognized keys outright.
_CATEGORIES = ("roles", "permissions", "principals", "constraints", "resource_types")


def _str_set(value: Any, where: str) -> frozenset[str] | None:
    """A JSON string array → frozenset; None (key not captured) passes through."""
    if value is None:
        return None
    if isinstance(value, (str, bytes, Mapping)) or not hasattr(value, "__iter__"):
        raise ValueError(f"snapshot.{where} must be an array of strings, got {type(value).__name__}")
    out = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ValueError(f"snapshot.{where} entries must be non-empty strings, got {item!r}")
        out.append(item)
    return frozenset(out)


def _record_map(value: Any, where: str) -> dict[str, dict[str, Any]] | None:
    """A JSON object of name → record-object; None passes through."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError(f"snapshot.{where} must be an object mapping names to records, "
                         f"got {type(value).__name__}")
    out: dict[str, dict[str, Any]] = {}
    for name, record in value.items():
        if not isinstance(name, str) or not name:
            raise ValueError(f"snapshot.{where} keys must be non-empty strings, got {name!r}")
        if not isinstance(record, Mapping):
            raise ValueError(f"snapshot.{where}[{name!r}] must be an object, "
                             f"got {type(record).__name__}")
        out[name] = dict(record)
    return out


@dataclass(frozen=True, eq=True)
class GcpSnapshot:
    """A point-in-time, offline snapshot of the vocabulary of a GCP estate.

    ``None`` in any category field means *not captured* (→ lookups answer
    :data:`UNKNOWN`); an empty collection means *captured and empty*
    (→ lookups answer ``False``).
    """

    #: ISO-8601 capture timestamp; every verdict is only as fresh as this.
    captured_at: str
    #: role name → record ({"title", "stage", "included_permissions", ...}).
    roles: dict[str, dict[str, Any]] | None = None
    #: flat enumeration of permission names (e.g. from queryTestablePermissions).
    permissions: frozenset[str] | None = None
    #: principal identifiers ("user:…", "serviceAccount:…", "group:…", …).
    principals: frozenset[str] | None = None
    #: org-policy constraint name → record ({"value_type": "boolean"|"list", ...}).
    constraints: dict[str, dict[str, Any]] | None = None
    #: asset types (e.g. "compute.googleapis.com/Instance").
    resource_types: frozenset[str] | None = None

    # -- construction ---------------------------------------------------------

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "GcpSnapshot":
        """Load a snapshot from a JSON file. Offline; raises ValueError with
        the path on malformed content."""
        with open(path, encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f"snapshot {path}: not valid JSON: {exc}") from exc
        try:
            snapshot = cls.from_dict(data)
        except ValueError as exc:
            raise ValueError(f"snapshot {path}: {exc}") from exc
        logger.debug("loaded snapshot %s (captured_at=%s, captured=%s)", path,
                     snapshot.captured_at, ",".join(snapshot.captured_categories()) or "none")
        return snapshot

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GcpSnapshot":
        if not isinstance(data, Mapping):
            raise ValueError(f"snapshot must be a mapping, got {type(data).__name__}")
        unrecognized = sorted(set(data) - {"captured_at", *_CATEGORIES})
        if unrecognized:
            raise ValueError(f"unrecognized snapshot keys {unrecognized} — a typo would "
                             f"silently demote a category to UNKNOWN; expected only "
                             f"'captured_at' and {list(_CATEGORIES)}")
        captured_at = data.get("captured_at")
        if not isinstance(captured_at, str) or not captured_at:
            raise ValueError("'captured_at' (non-empty ISO-8601 string) is required — "
                             "verdicts must be stampable with snapshot freshness")

        roles = _record_map(data.get("roles"), "roles")
        if roles is not None:
            for name, record in roles.items():
                if "included_permissions" not in record:
                    continue
                perms = record["included_permissions"]
                if perms is None:
                    raise ValueError(
                        f"snapshot.roles[{name!r}].included_permissions must be an "
                        f"array of strings, got null — omit the key when the role's "
                        f"permissions were not captured")
                got = _str_set(perms, f"roles[{name!r}].included_permissions")
                record["included_permissions"] = tuple(sorted(got or ()))

        constraints = _record_map(data.get("constraints"), "constraints")
        if constraints is not None:
            for name, record in constraints.items():
                value_type = record.get("value_type")
                if not isinstance(value_type, str) or not value_type:
                    raise ValueError(f"constraints[{name!r}] needs a 'value_type' string "
                                     f"(e.g. 'boolean' or 'list') — without it wrong-typed "
                                     f"usage cannot be contradicted")

        return cls(
            captured_at=captured_at,
            roles=roles,
            permissions=_str_set(data.get("permissions"), "permissions"),
            principals=_str_set(data.get("principals"), "principals"),
            constraints=constraints,
            resource_types=_str_set(data.get("resource_types"), "resource_types"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Inverse of :meth:`from_dict`: only captured categories appear, all
        collections sorted, so dumps are deterministic and round-trips exact."""
        out: dict[str, Any] = {"captured_at": self.captured_at}
        if self.roles is not None:
            out["roles"] = {}
            for name in sorted(self.roles):
                record = dict(self.roles[name])
                if "included_permissions" in record:
                    record["included_permissions"] = list(record["included_permissions"])
                out["roles"][name] = record
        if self.permissions is not None:
            out["permissions"] = sorted(self.permissions)
        if self.principals is not None:
            out["principals"] = sorted(self.principals)
        if self.constraints is not None:
            out["constraints"] = {name: dict(self.constraints[name])
                                  for name in sorted(self.constraints)}
        if self.resource_types is not None:
            out["resource_types"] = sorted(self.resource_types)
        return out

    def captured_categories(self) -> tuple[str, ...]:
        """Which categories this snapshot actually enumerated."""
        return tuple(c for c in _CATEGORIES if getattr(self, c) is not None)

    # -- conservative lookups -------------------------------------------------
    #
    # Contract: True = exists in the snapshot; False = the category was
    # enumerated and the name is not in it; UNKNOWN = the category was never
    # captured, so absence of evidence is not evidence of absence.

    def role_exists(self, name: str) -> bool | Unknown:
        if self.roles is None:
            return UNKNOWN
        return name in self.roles

    def permission_exists(self, name: str) -> bool | Unknown:
        """Membership in the permission enumeration, or — since a permission a
        real role includes necessarily exists — in any role's
        ``included_permissions``. Only an explicit enumeration can prove
        absence; the union over captured roles is not one."""
        if self.permissions is not None and name in self.permissions:
            return True
        if self.roles is not None and name in self._role_included_permissions:
            return True
        if self.permissions is not None:
            return False
        return UNKNOWN

    def principal_exists(self, name: str) -> bool | Unknown:
        if self.principals is None:
            return UNKNOWN
        return name in self.principals

    def constraint(self, name: str) -> Mapping[str, Any] | None | Unknown:
        """The constraint record (carrying ``value_type``) — or None if
        constraints were enumerated and this one does not exist, or UNKNOWN
        if constraints were never captured."""
        if self.constraints is None:
            return UNKNOWN
        return self.constraints.get(name)

    def resource_type_exists(self, name: str) -> bool | Unknown:
        if self.resource_types is None:
            return UNKNOWN
        return name in self.resource_types

    @cached_property
    def _role_included_permissions(self) -> frozenset[str]:
        found: set[str] = set()
        for record in (self.roles or {}).values():
            # `or ()`: from_dict rejects a null included_permissions, but a
            # hand-constructed snapshot may still carry None — read it as
            # "nothing included", never crash.
            found.update(record.get("included_permissions") or ())
        return frozenset(found)
