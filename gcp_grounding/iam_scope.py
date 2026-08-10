"""The predefined-to-custom role swap, scope-diffed against the current grant.

The story this check exists for: an operator swaps a binding's predefined role
for a ``google_project_iam_custom_role`` defined in the SAME proposal, intending
to reduce the binding's permission scope — and accidentally includes a
permission the predefined role never granted. Every existing channel is silent
or abstains about exactly that accident: the permission-existence pass grounds
each entry (the extra permission EXISTS), the escalation check reads the
binding's role out of the snapshot (a role being created is not in it), and the
``[subset]`` widening note sees only that the role STRING changed, honestly
abstaining over a partial baseline. This module is the decision layer for the
diff itself, wired in through the lazy provider :mod:`gcp_grounding.registry`:

- CHECK — :func:`check_role_scope_diff` (``DOCUMENT_CHECKS``): when a terraform
  proposal both DEFINES a custom role and BINDS it, and the current state shows
  the same binding (same project, same member set) previously granting a
  DIFFERENT role whose permissions the snapshot enumerates, the two permission
  sets are compared. Extras (new − old) are a **warning riding on a
  ``grounded`` verdict** — non-blocking on purpose, mirroring
  :func:`gcp_grounding.iam_checks.check_escalation`'s verdict polarity, because
  "mostly a reduction" is not a violation and consequence is the promise
  layer's job (a compiled promise over ``proposed_role_permissions`` is what
  turns a forbidden extra into a block). The message names every extra
  permission (annotated with its :data:`gcp_grounding.iam_checks
  .ESCALATION_PERMISSIONS` class when it has one) and the custom-role block
  address an operator must edit. A swap that adds nothing is affirmed as a
  scope reduction, extras counted at zero and drops counted exactly.

VERDICT POLARITY. This check NEVER blocks by itself: its findings are warnings
on ``grounded`` verdicts, exactly like the escalation table's, because the
accident it surfaces is a fact about intent ("reducing scope" is only mostly
true) and not by itself a violation of anything.

ABSTENTION. Every absence that cannot be proven abstains by name instead of
passing: a current state that never captured ``iam_bindings``; a captured table
with no record for the binding's project (partial coverage proves no absence);
a previous role the snapshot does not enumerate, or enumerates without its
``included_permissions``; an ambiguous predecessor (two current roles granted
to exactly this member set); a conditional predecessor; a binding or custom
role whose ``count``/``for_each`` multiplicity, project, members or permission
list cannot be read. A proposal that does no swap — no custom role, no binding
naming one, a REST document — is the one honest silence: there is nothing this
check could have decided.

EVIDENCE AND DRIFT. Snapshot reads go through the snapshot's own accessors and
:mod:`gcp_grounding.evidence`, so the registry's evidence floor counts what was
examined and the drift guard adjudicates the verdict against the estate facts
it actually touched — a warning resting on a stale or disputed role enumeration
is downgraded to ``unverified`` carrying the same text, never silently trusted.

**No z3 anywhere.** Every decision is set arithmetic over enumerated permission
lists, identical on the ``z3`` and ``builtin`` solver backends.
"""

from __future__ import annotations

from typing import Any, Iterator, Mapping

from . import evidence, identity
from .core.log import get_logger
from .core.report import Verdict
from .iam_checks import ESCALATION_PERMISSIONS
from .knowledge import UNKNOWN

logger = get_logger(__name__)

__all__ = ["DOCUMENT_CHECKS", "check_role_scope_diff"]

#: The verdict kind every verdict here carries. Listed among the JUDGMENT kinds
#: of the CLI decision block's abstention taste, so a drift-downgraded warning
#: still leads the narrative instead of trailing the coverage noise.
KIND = "iam_scope_diff"

#: The one resource type that defines a custom role in a proposal.
_CUSTOM_ROLE_TYPE = "google_project_iam_custom_role"

#: The binding-shaped resource the swap story is about. A ``*_iam_member`` is
#: deliberately NOT read: it is additive (the old grant persists beside it), so
#: there is no "same binding previously granting a different role" to diff.
_BINDING_TYPE = "google_project_iam_binding"

#: The document kind this check reads. Everything else is silence: the shapes
#: below (block addresses, planned values) exist only in a terraform proposal.
_TF_PLAN = "tf_plan"


def check_role_scope_diff(ctx: Any) -> list["Verdict"]:
    """Scope-diff verdicts for every custom-role swap this proposal performs.

    Document-level rather than claim-level because the decision needs THREE
    parties no single claim carries together: the custom-role block (the new
    permission set), the binding block (who gets it, where), and the current
    state (what that binding granted before).
    """
    if getattr(ctx, "document_kind", None) != _TF_PLAN:
        return []
    document = getattr(ctx, "document", None)
    if not isinstance(document, Mapping):
        return []
    customs: dict[str, Any] = {}
    bindings: dict[str, Any] = {}
    for address, rtype, values in _google_resources(document):
        if rtype == _CUSTOM_ROLE_TYPE:
            customs[address] = values
        elif rtype == _BINDING_TYPE:
            bindings[address] = values
    if not customs:
        return []  # nothing is being defined, so nothing can be swapped in

    verdicts: list[Verdict] = []
    names: dict[str, str] = {}  # full role name -> defining block address
    for address in sorted(customs):
        values = customs[address]
        if not isinstance(values, Mapping):
            if bindings:
                verdicts.append(_undecided(
                    address, f"{address}: this custom role has no readable "
                             f"planned values — whether the proposal swaps it "
                             f"into a binding was not decided"))
            continue
        role_id = values.get("role_id")
        project = values.get("project")
        if (isinstance(role_id, str) and role_id
                and isinstance(project, str) and project):
            names[f"projects/{project}/roles/{role_id}"] = address
        elif bindings:
            verdicts.append(_undecided(
                address, f"{address}: this custom role's 'role_id'/'project' "
                         f"could not be read from the configuration, so its "
                         f"full name — and whether any binding in this "
                         f"proposal grants it — was not decided"))

    for address in sorted(bindings):
        values = bindings[address]
        if not isinstance(values, Mapping):
            continue  # tf_claims already logs it; there is no role to match
        role = values.get("role")
        if not isinstance(role, str) or not role:
            # The common spelling of a swap is exactly a role reference the
            # static resolver stripped; silence here would read as "no swap".
            verdicts.append(_undecided(
                address, f"{address}: this binding's role could not be read "
                         f"from the configuration, and this proposal defines "
                         f"custom role(s) ({', '.join(sorted(customs))}) — "
                         f"whether it swaps one of them in was not decided"))
            continue
        if role not in names:
            continue  # binds something this proposal does not define
        verdict = _swap_verdict(ctx, address, values, role, names[role],
                                customs[names[role]])
        if verdict is not None:
            verdicts.append(verdict)
    return verdicts


def _swap_verdict(ctx: Any, binding: str, values: Mapping[str, Any],
                  new_role: str, custom: str,
                  custom_values: Mapping[str, Any]) -> Verdict | None:
    """The one verdict for a binding that grants a proposal-defined custom role
    — the diff, or the named reason it could not be computed."""
    for address, block in ((binding, values), (custom, custom_values)):
        for meta in ("count", "for_each"):
            if meta in block:
                return _undecided(
                    new_role, f"{binding}: {address} carries {meta!r}, so how "
                              f"many instances the block creates is not "
                              f"decided from the configuration — the scope "
                              f"diff was not computed")

    project = values.get("project")
    if not isinstance(project, str) or not project:
        return _undecided(
            new_role, f"{binding}: this binding grants the custom role defined "
                      f"at {custom} but names no readable 'project', so the "
                      f"current grant it replaces was not located — the scope "
                      f"diff was not computed")
    try:
        members = evidence.rows(values, "members", what=f"IAM binding {binding}")
    except evidence.NotEvaluated as exc:
        return _undecided(
            new_role, f"{binding}: this binding grants the custom role defined "
                      f"at {custom} but {exc.reason} — without its members the "
                      f"current grant it replaces cannot be identified, so the "
                      f"scope diff was not computed")
    if not members:
        logger.debug("%s: members present and empty — the binding grants "
                     "nobody, so there is no grant to diff", binding)
        return None
    if any(not isinstance(m, str) or not m for m in members):
        return _undecided(
            new_role, f"{binding}: this binding's members include entries that "
                      f"are not plain principal ids — the grantee could not be "
                      f"identified, so the scope diff was not computed")

    try:
        key = identity.canonical_key("iam_bindings", name=f"projects/{project}")
    except identity.AmbiguousKey as exc:
        return _undecided(
            new_role, f"{binding}: no current-state key could be built for "
                      f"project {project!r} ({exc}) — the scope diff was not "
                      f"computed")
    # A snapshot without the accessor at all is the same "not captured" answer
    # as UNKNOWN — the convention _estate_table already spells for tables.
    accessor = getattr(ctx.snapshot, "iam_binding_set", None)
    record = accessor(key) if callable(accessor) else UNKNOWN
    if record is UNKNOWN:
        return _undecided(
            new_role, f"{binding}: the current state did not capture "
                      f"iam_bindings, so what this binding granted before the "
                      f"swap to {new_role} ({custom}) is unknown — the scope "
                      f"diff was not computed")
    if record is None:
        return _undecided(
            new_role, f"{binding}: the current state holds no iam_bindings "
                      f"record for {key} — coverage of this category is not "
                      f"proof of absence, so what this binding granted before "
                      f"was not decided and the scope diff was not computed")
    what = f"the current bindings of {key}"
    try:
        current = evidence.scalar(record, "bindings", what=what, type=tuple)
    except evidence.NotEvaluated as exc:
        return _undecided(
            new_role, f"{binding}: the current record for {key} {exc.reason} — "
                      f"the scope diff was not computed")
    evidence.examined(len(current), what=what)

    predecessor = _predecessor(binding, new_role, frozenset(members), current,
                               key)
    if not isinstance(predecessor, str):
        return predecessor  # a Verdict (abstention) or None (no swap visible)
    old_role = predecessor

    old_permissions = _enumerated(ctx.snapshot, old_role, binding)
    if isinstance(old_permissions, Verdict):
        return old_permissions
    what = f"custom role {custom}"
    try:
        new_permissions = evidence.rows(custom_values, "permissions", what=what)
    except evidence.NotEvaluated as exc:
        return _undecided(
            new_role, f"{binding}: the custom role at {custom} {exc.reason} — "
                      f"its permission set was not read, so the scope diff "
                      f"was not computed")
    if any(not isinstance(p, str) or not p for p in new_permissions):
        return _undecided(
            new_role, f"{binding}: the custom role at {custom} carries "
                      f"permission entries that are not plain permission names "
                      f"— its permission set was not read, so the scope diff "
                      f"was not computed")

    extras = sorted(set(new_permissions) - set(old_permissions))
    dropped = sorted(set(old_permissions) - set(new_permissions))
    if extras:
        rendered = ", ".join(_classified(p) for p in extras)
        return Verdict(
            "grounded", KIND, new_role, 0,
            f"{binding}: warning — this change swaps {old_role} for {new_role} "
            f"({custom}) on the same binding, and the custom role adds "
            f"{len(extras)} permission(s) {old_role} never granted: {rendered} "
            f"— the swap is not only a scope reduction; review {custom}")
    return Verdict(
        "grounded", KIND, new_role, 0,
        f"{binding}: this change swaps {old_role} for {new_role} ({custom}), "
        f"and every permission the custom role includes was already granted by "
        f"{old_role} — a scope reduction ({len(dropped)} of "
        f"{len(old_permissions)} permission(s) dropped, none added)")


def _predecessor(binding: str, new_role: str, wanted: frozenset,
                 current: tuple, key: str) -> "str | Verdict | None":
    """The role the current state granted to exactly this member set — or the
    named abstention, or None when no predecessor is visible.

    None is the one silence: a brand-new binding has no predecessor to diff,
    and whether it widens anything is the ``[subset]`` channel's question, not
    this check's. An UNREADABLE current entry is never silently skipped past a
    miss — a predecessor may be hiding inside it."""
    old_roles: dict[str, Any] = {}
    unreadable = 0
    for entry in current:
        if not isinstance(entry, Mapping):
            unreadable += 1
            continue
        role = entry.get("role")
        members = entry.get("members")
        if (not isinstance(role, str) or not role
                or not isinstance(members, (list, tuple))
                or any(not isinstance(m, str) for m in members)):
            unreadable += 1
            continue
        if frozenset(members) == wanted and role != new_role:
            old_roles.setdefault(role, entry)
    if not old_roles:
        if unreadable:
            return _undecided(
                new_role, f"{binding}: {unreadable} of {key}'s current binding "
                          f"record(s) could not be read, and the predecessor "
                          f"of this binding may be among them — the scope diff "
                          f"was not computed")
        logger.debug("%s: no current binding grants a different role to exactly "
                     "these members — no predecessor to diff", binding)
        return None
    if len(old_roles) > 1:
        return _undecided(
            new_role, f"{binding}: the current state grants "
                      f"{', '.join(sorted(old_roles))} to exactly this member "
                      f"set — which of them this binding replaces is ambiguous, "
                      f"so the scope diff was not computed")
    (old_role, entry), = old_roles.items()
    if entry.get("condition") not in (None, ""):
        return _undecided(
            new_role, f"{binding}: the current grant of {old_role} to this "
                      f"member set is conditional — what it granted "
                      f"unconditionally was not decided, so the scope diff was "
                      f"not computed")
    return old_role


def _enumerated(snapshot: Any, role: str, binding: str) -> "tuple | Verdict":
    """*role*'s enumerated permission set, or the named abstention.

    Mirrors :func:`gcp_grounding.iam_checks._escalation_verdict`'s reading of
    the same record, including the absent-OR-empty ``included_permissions``
    collapse: both mean nothing was captured, and an uncaptured set differenced
    against anything fabricates either extras or their absence."""
    exists = snapshot.role_exists(role)
    if exists is UNKNOWN:
        return _undecided(
            role, f"{binding}: the snapshot did not capture roles, so the "
                  f"permission set of the previous role {role} is unknown — "
                  f"the scope diff was not computed")
    if exists is False:
        return _undecided(
            role, f"{binding}: the previous role {role} is not in the "
                  f"snapshot's role enumeration — its permission set cannot "
                  f"anchor a scope diff, so nothing was decided")
    what = f"the snapshot's record for {role}"
    try:
        record = evidence.scalar(snapshot.roles, role, what=what, type=dict)
        permissions = evidence.scalar(record, "included_permissions",
                                      what=what, type=tuple)
    except evidence.NotEvaluated as exc:
        return _undecided(
            role, f"{binding}: the snapshot captured {role} but {exc.reason} — "
                  f"an uncaptured permission set cannot anchor a scope diff, "
                  f"so nothing was decided")
    evidence.examined(len(permissions), what=what)
    if not permissions:
        return _undecided(
            role, f"{binding}: the snapshot captured {role} but not its "
                  f"included_permissions (present and holding no permissions) "
                  f"— an uncaptured permission set cannot anchor a scope diff, "
                  f"so nothing was decided")
    return permissions


def _classified(permission: str) -> str:
    """*permission*, annotated with its curated escalation class when it has
    one — the annotation is what makes an accidental ``actAs`` read as the
    escalation it is, in the same vocabulary the escalation check uses."""
    escalation_class = ESCALATION_PERMISSIONS.get(permission)
    return (f"{permission} ({escalation_class})" if escalation_class
            else permission)


def _undecided(target: str, message: str) -> Verdict:
    return Verdict("unverified", KIND, target, 0, message)


def _google_resources(document: Mapping[str, Any]
                      ) -> Iterator[tuple[str, str, Any]]:
    """(address, type, planned values) — through ``tf_claims``' OWN plan walker,
    resolved lazily so a checkout without the terraform extractor keeps this
    check silent instead of broken (the same degradation as
    ``preflight._tf_plan_extractor``)."""
    try:
        from . import tf_claims
    except ImportError:
        logger.debug("tf_claims is not part of this checkout — the scope diff "
                     "has no plan walker and stays silent")
        return
    yield from tf_claims._google_resources(document)


#: Registry hook consulted by :mod:`gcp_grounding.preflight` — see
#: :mod:`gcp_grounding.registry`.
DOCUMENT_CHECKS = (check_role_scope_diff,)
