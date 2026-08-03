"""Offline checks for the missing half of IAM: public exposure and escalation.

:mod:`~gcp_grounding.claims` and :mod:`~gcp_grounding.iam_deny` already *record*
the two facts that used to hide in a byte-identical clean report — a binding
naming ``allUsers``/``allAuthenticatedUsers``, and the permissions an IAM deny
policy names — but nothing decided them, so every such claim fell through to
:func:`~gcp_grounding.preflight.ground_policy`'s honest catch-all and passed.
This module is the decision layer, wired in through the lazy provider
:mod:`~gcp_grounding.registry`:

- CHECK A — :func:`check_public_principal` (``CLAIM_CHECKS["public_principal"]``)
  turns a *grant* of a public principal into a ``contradicted`` verdict and a
  *denial* of one into a ``grounded`` verdict. The polarity is what separates an
  exposure from a guardrail; it rides on the claim payload.
- CHECK B — :func:`check_escalation` (``DOCUMENT_CHECKS``) correlates each
  binding's role with that binding's members and reports the privilege-escalation
  classes the role's permissions unlock.
- CHECK C — :func:`check_denied_permission`
  (``CLAIM_CHECKS["denied_permission"]``) names the escalation class an IAM deny
  rule blocks, so a deny policy no longer produces a wall of catch-all
  ``unverified`` verdicts.

**No z3 anywhere.** Every decision here is a set lookup or a string comparison,
so the module behaves identically on the ``z3`` and ``builtin`` solver backends
— the accompanying tests assert that explicitly.

THE STATIC TABLE. :data:`ESCALATION_PERMISSIONS` and :data:`ESCALATION_ROLES`
are committed constants, deliberately **not** a ``fetch.py`` capture: they are
*curated security knowledge* (which permission lets a principal become another
principal), not estate state, so they are versioned with the code, reviewed like
code, and identical on every machine — a snapshot could never supply them. The
curation is intentionally **conservative**: it lists permissions whose escalation
path is direct and well documented, and omits the long tail of
service-specific pivots, because a table that fires on everything gets disabled.
Entries are grouped into six classes — ``impersonation``, ``role-mutation``,
``policy-mutation``, ``guardrail-removal``, ``build-pivot`` and
``surface-expansion`` — plus ``named-admin-role`` for membership in
:data:`ESCALATION_ROLES`.

VERDICT POLARITY. A hit granted to a *public* principal is ``contradicted``: it
blocks, because anyone on the internet can take the escalation path. A hit
granted to ordinary principals is a **warning riding on a ``grounded``
verdict** — non-blocking on purpose, mirroring the tautology warning in
:func:`~gcp_grounding.constraints.check_cel`, because ``roles/editor``
legitimately appears in real policies and a guardrail that cries wolf gets
switched off. No hit at all yields no verdict, so benign bindings stay quiet.

ABSTENTION. Every path that cannot see its inputs says so instead of passing:
roles not captured, a role record without ``included_permissions``, and — the
case the naive pairing rule would have swallowed — a ``role`` claim whose
location fits neither the ``bindings[<i>]`` shape nor a terraform resource
address, where "no hit means no verdict" would silently drop the escalation
check for that binding rather than admit the pairing failed.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from .core.log import get_logger
from .core.report import Verdict
from .knowledge import UNKNOWN

logger = get_logger(__name__)

__all__ = [
    "ESCALATION_PERMISSIONS", "ESCALATION_ROLES", "CLAIM_CHECKS",
    "DOCUMENT_CHECKS", "check_public_principal", "check_escalation",
    "check_denied_permission",
]

#: CURATED, versioned with the code, intentionally conservative: IAM permission
#: → the privilege-escalation class it unlocks. Not a snapshot category and
#: never fetched — this is security knowledge, not estate state.
ESCALATION_PERMISSIONS: Mapping[str, str] = {
    # Becoming another principal.
    "iam.serviceAccounts.actAs": "impersonation",
    "iam.serviceAccounts.getAccessToken": "impersonation",
    "iam.serviceAccounts.getOpenIdToken": "impersonation",
    "iam.serviceAccounts.implicitDelegation": "impersonation",
    "iam.serviceAccounts.signBlob": "impersonation",
    "iam.serviceAccounts.signJwt": "impersonation",
    "iam.serviceAccountKeys.create": "impersonation",
    "compute.instances.setServiceAccount": "impersonation",
    # Rewriting what a role means.
    "iam.roles.create": "role-mutation",
    "iam.roles.update": "role-mutation",
    "iam.roles.delete": "role-mutation",
    "iam.roles.undelete": "role-mutation",
    # Granting yourself anything.
    "resourcemanager.projects.setIamPolicy": "policy-mutation",
    "resourcemanager.folders.setIamPolicy": "policy-mutation",
    "resourcemanager.organizations.setIamPolicy": "policy-mutation",
    "iam.serviceAccounts.setIamPolicy": "policy-mutation",
    "storage.buckets.setIamPolicy": "policy-mutation",
    "cloudfunctions.functions.setIamPolicy": "policy-mutation",
    "run.services.setIamPolicy": "policy-mutation",
    "iam.denypolicies.update": "policy-mutation",
    # Switching the guardrails off.
    "orgpolicy.policy.set": "guardrail-removal",
    "orgpolicy.customConstraints.update": "guardrail-removal",
    "accesscontextmanager.policies.setIamPolicy": "guardrail-removal",
    # Running code as a privileged builder/runner service account.
    "cloudbuild.builds.create": "build-pivot",
    "deploymentmanager.deployments.create": "build-pivot",
    "dataflow.jobs.create": "build-pivot",
    "composer.environments.create": "build-pivot",
    # Turning on new attack surface.
    "serviceusage.services.enable": "surface-expansion",
}

#: CURATED: predefined roles that are an escalation path by name, whatever the
#: snapshot captured for their permission set. Membership counts as a hit of
#: class :data:`_NAMED_ADMIN_ROLE`.
ESCALATION_ROLES = frozenset({
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/iam.roleAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.workloadIdentityPoolAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/orgpolicy.policyAdmin",
})

#: The class recorded for an :data:`ESCALATION_ROLES` membership hit.
_NAMED_ADMIN_ROLE = "named-admin-role"

#: How many hits / members one message enumerates before "+N more".
_RENDER_CAP = 3

#: A binding-index location prefix, e.g. ``bindings[3]`` — the API-document
#: anchoring produced by :func:`~gcp_grounding.claims.iam_policy_claims`.
_BINDING_PREFIX = re.compile(r"^bindings\[\d+\]$")

#: A terraform resource address, optionally nested in modules and optionally
#: indexed: ``google_project_iam_member.public``,
#: ``module.iam.google_project_iam_binding.viewers["a"]``. Only google-provider
#: types are anchored this way, which is what keeps an arbitrary dotted path
#: (``spec.somewhere``) from being mistaken for an address.
_TF_ADDRESS = re.compile(
    r"^(?:module\.[A-Za-z0-9_-]+(?:\[[^\]]+\])?\.)*"
    r"google[A-Za-z0-9_]*\.[A-Za-z0-9_-]+(?:\[[^\]]+\])?$")

#: The ``policy_data`` hop between a terraform address and a binding index, as
#: emitted for ``google_project_iam_policy``.
_POLICY_DATA = ".policy_data."

#: Claim kinds that name a member of a binding, for the pairing step.
_MEMBER_KINDS = ("principal", "public_principal")


# -- CHECK A: public principals -----------------------------------------------


def check_public_principal(claim: Any, ctx: Any) -> Verdict:
    """Verdict for one ``public_principal`` claim.

    A *grant* of ``allUsers``/``allAuthenticatedUsers`` makes the resource
    world-readable (or worse) and is ``contradicted`` — this is the verdict that
    turns the worst silent pass into a block. The same member named by an IAM
    *deny* policy is a guardrail and is ``grounded``. A claim carrying neither
    polarity is not guessed at.
    """
    member = claim.value
    where = claim.location or "policy"
    fields = claim.fields() if hasattr(claim, "fields") else {}
    polarity = fields.get("polarity")
    if polarity == "deny":
        return Verdict("grounded", "iam_public", member, 0,
                       f"{where}: denying {member} is a guardrail, not an exposure")
    if polarity == "grant":
        role = fields.get("role") or "an unnamed role"
        return Verdict("contradicted", "iam_public", member, 0,
                       f"{where}: binding grants {role} to {member} — the resource "
                       f"becomes publicly accessible")
    logger.debug("%s: public_principal claim carries polarity %r — abstaining",
                 where, polarity)
    return Verdict("unverified", "iam_public", member, 0,
                   f"{where}: this {member} claim carries no grant/deny polarity — "
                   f"whether it is an exposure or a guardrail was not decided")


# -- CHECK B: the curated permission-to-escalation-class check ----------------


def check_escalation(ctx: Any) -> list[Verdict]:
    """Escalation verdicts for every binding in the document.

    Document-level rather than claim-level because the decision needs *both*
    halves of a binding: the role names the permissions, the members name who
    gets them, and only the whole claim list has both.
    """
    claims = tuple(getattr(ctx, "claims", ()) or ())
    members = [c for c in claims if c.kind in _MEMBER_KINDS]
    verdicts: list[Verdict] = []
    for claim in claims:
        if claim.kind != "role":
            continue
        verdict = _escalation_verdict(claim, members, ctx.snapshot)
        if verdict is not None:
            verdicts.append(verdict)
    return verdicts


def _escalation_verdict(claim: Any, members: list[Any], snapshot: Any) -> Verdict | None:
    role = claim.value
    where = claim.location or "policy"

    # ABSTAIN ON AN UNGROUPABLE LOCATION — checked first, so this stays the
    # single verdict for such a claim. A location the pairing step cannot read
    # is indistinguishable from a benign binding, and staying silent would drop
    # the escalation check for it without ever saying so.
    key = _binding_key(claim.location)
    if key is None:
        logger.debug("%s: role location fits neither bindings[i] nor a terraform "
                     "address — abstaining", where)
        return Verdict("unverified", "iam_escalation", role, 0,
                       f"{where}: could not associate this role with its members "
                       f"— escalation classes were not decided")

    exists = snapshot.role_exists(role)
    if exists is UNKNOWN:
        return Verdict("unverified", "iam_escalation", role, 0,
                       "snapshot did not capture roles — escalation classes "
                       "were not decided")
    if exists is False:
        # The Datalog existence pass already reports this role as ungrounded;
        # a role that does not exist grants no permissions, so there is nothing
        # further to decide here.
        logger.debug("%s: %s is not in the snapshot — the existence pass owns it",
                     where, role)
        return None
    record = (snapshot.roles or {}).get(role) or {}
    if "included_permissions" not in record:
        return Verdict("unverified", "iam_escalation", role, 0,
                       f"{where}: the snapshot captured {role} but not its "
                       f"included_permissions — escalation classes were not decided")

    hits = _hits(role, record["included_permissions"])
    if not hits:
        return None  # a benign binding stays quiet

    bound = [c for c in members if c.location.startswith(f"{key}.")]
    public = [c for c in bound if _is_public(c)]
    rendered = _capped(f"{name} ({cls})" for name, cls in hits)
    if public:
        return Verdict("contradicted", "iam_escalation", role, 0,
                       f"{where}: {role} grants {rendered} to "
                       f"{_capped(c.value for c in public)} — anyone can escalate")
    if not bound:
        return Verdict("grounded", "iam_escalation", role, 0,
                       f"{where}: warning — {role} grants {rendered}, but no members "
                       f"were extracted from this binding; review the principals")
    return Verdict("grounded", "iam_escalation", role, 0,
                   f"{where}: warning — {role} grants {rendered} to "
                   f"{_capped(c.value for c in bound)}; review the principal")


def _hits(role: str, permissions: Iterable[str]) -> list[tuple[str, str]]:
    """The (name, class) escalation hits for *role*: its membership in
    :data:`ESCALATION_ROLES` first, then its escalation permissions by name."""
    hits: list[tuple[str, str]] = []
    if role in ESCALATION_ROLES:
        hits.append((role, _NAMED_ADMIN_ROLE))
    hits.extend((perm, ESCALATION_PERMISSIONS[perm])
                for perm in sorted(set(permissions) & set(ESCALATION_PERMISSIONS)))
    return hits


def _is_public(claim: Any) -> bool:
    """Whether a paired member claim opens the binding to the public. A
    ``public_principal`` explicitly carrying ``polarity="deny"`` came from a
    deny policy and is a guardrail; anything else public-kinded counts."""
    if claim.kind != "public_principal":
        return False
    fields = claim.fields() if hasattr(claim, "fields") else {}
    return fields.get("polarity") != "deny"


def _binding_key(location: Any) -> str | None:
    """The location prefix a binding's member claims share with its ``role``
    claim — or None when the location is not a shape the pairing step reads.

    Three anchorings are recognized: ``bindings[<i>].role`` from an API
    document, ``<tf address>.role`` from ``google_project_iam_binding`` /
    ``google_project_iam_member``, and
    ``<tf address>.policy_data.bindings[<i>].role`` from
    ``google_project_iam_policy`` (which keeps two bindings of one resource
    apart instead of merging them under the bare address).
    """
    if not isinstance(location, str) or not location.endswith(".role"):
        return None
    prefix = location[: -len(".role")]
    if _BINDING_PREFIX.match(prefix):
        return prefix
    head, sep, tail = prefix.rpartition(_POLICY_DATA)
    if sep and _BINDING_PREFIX.match(tail) and _TF_ADDRESS.match(head):
        return prefix
    if _TF_ADDRESS.match(prefix):
        return prefix
    return None


def _capped(items: Iterable[str], cap: int = _RENDER_CAP) -> str:
    """``a, b, c +N more`` — enumerate at most *cap* items so one verdict line
    stays readable however wide the binding is."""
    values = list(items)
    shown = ", ".join(values[:cap])
    extra = len(values) - cap
    return f"{shown} +{extra} more" if extra > 0 else shown


# -- CHECK C: permissions an IAM deny policy names ----------------------------


def check_denied_permission(claim: Any, ctx: Any) -> Verdict:
    """Verdict for one ``denied_permission`` claim from an IAM deny policy.

    A deny rule naming an escalation-class permission is GOOD news, so it is
    ``grounded`` with the class named. The normalized short form is read off the
    sibling ``permission`` claim the extractor emitted at the same location; when
    it declined to derive one (a wildcard, a shape it will not guess at) there is
    no sibling, and this abstains naming the raw string rather than passing.
    """
    raw = claim.value
    where = claim.location or "policy"
    excepted = bool(claim.fields().get("excepted")) if hasattr(claim, "fields") else False
    normalized = _normalized_permission(claim, ctx)
    if normalized is None:
        return Verdict("unverified", "iam_escalation", raw, 0,
                       f"{where}: {raw} has no unambiguous normalized permission "
                       f"name — its escalation class was not decided")
    escalation_class = ESCALATION_PERMISSIONS.get(normalized)
    if escalation_class is None:
        return Verdict("grounded", "iam_escalation", normalized, 0,
                       f"{where}: {normalized} is not in the curated escalation "
                       f"table — this rule names no known escalation path")
    if excepted:
        return Verdict("grounded", "iam_escalation", normalized, 0,
                       f"{where}: warning — {normalized} ({escalation_class}) is "
                       f"excepted from this deny rule, so the denial does not "
                       f"cover it; review the exception")
    return Verdict("grounded", "iam_escalation", normalized, 0,
                   f"{where}: denying {normalized} ({escalation_class}) blocks a "
                   f"known escalation path")


def _normalized_permission(claim: Any, ctx: Any) -> str | None:
    """The normalized short form of a ``denied_permission``: the value of the
    ``permission`` existence claim the extractor emitted at the same location,
    or None when it emitted none because the rewrite would have been a guess."""
    for other in tuple(getattr(ctx, "claims", ()) or ()):
        if other.kind == "permission" and other.location == claim.location:
            return other.value
    return None


#: Registry hooks consulted by :mod:`gcp_grounding.preflight` — see
#: :mod:`gcp_grounding.registry`.
CLAIM_CHECKS = {
    "public_principal": check_public_principal,
    "denied_permission": check_denied_permission,
}
DOCUMENT_CHECKS = (check_escalation,)
