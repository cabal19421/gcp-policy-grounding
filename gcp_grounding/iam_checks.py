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
  exposure from a guardrail; it rides on the claim payload — as does the
  ``excepted`` discriminator, without which a public principal EXEMPTED from a
  denial is indistinguishable from one the rule denies, and reporting the first
  as a guardrail asserts the reverse of the truth.
- CHECK B — :func:`check_escalation` (``DOCUMENT_CHECKS``) correlates each
  binding's role with that binding's members and reports the privilege-escalation
  classes the role's permissions unlock.
- CHECK C — :func:`check_denied_permission`
  (``CLAIM_CHECKS["denied_permission"]``) names the escalation class an IAM deny
  rule blocks, so a deny policy no longer produces a wall of catch-all
  ``unverified`` verdicts. A rule "blocks" only once its EXCEPTION principals
  have been read: the claim's ``rule_index`` payload is what finds the sibling
  claims of the same rule, and a rule exempting the public denies nobody.

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
roles not captured, a role record whose ``included_permissions`` is absent OR
present-and-empty (the fetch path always writes the key, so key presence never
meant capture), a deny rule whose exception principals cannot be classified, a
binding whose members were refused by the extractor or whose ``members`` key was
never captured, an IAM allow policy from which no role claim was extracted at
all, and — the case the naive pairing rule would have swallowed — a ``role``
claim whose location fits neither the ``bindings[<i>]`` shape nor a terraform
resource address, where "no hit means no verdict" would silently drop the
escalation check for that binding rather than admit the pairing failed.

EVIDENCE. Every collection this module reads goes through
:mod:`gcp_grounding.evidence`, so UNREADABLE and NEVER CAPTURED cannot fold into
NO RECORDS on the way to a verdict: a role's permission list, a policy's
``bindings`` and a binding's ``members``. The one place emptiness IS dispositive
— a ``members`` list that is present and observed empty — says so in the verdict
it emits.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from . import evidence
from .claims import PUBLIC_PRINCIPALS
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
#: anchoring produced by :func:`~gcp_grounding.claims.iam_policy_claims`. The
#: index is captured so :func:`_binding_members` can find the binding it names.
_BINDING_PREFIX = re.compile(r"^bindings\[(\d+)\]$")

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

#: Document kinds whose bindings carry roles. An IAM *deny* policy carries none
#: by construction, so "no role claim" says nothing about one; an allow policy
#: with no role claim is a document whose roles were all skipped.
_ROLE_BEARING_KINDS = ("iam_policy",)

#: What every no-usable-members abstention has to say, spelled once: the point
#: of the split is that public exposure was left UNDECIDED, not ruled out.
_UNDECIDED_GRANTEE = "whether the grantee is public was not decided"

#: The ``rules[<i>].denyRule.`` segment a deny claim's ``rule_index`` names, and
#: the exception-principal field inside it. Locations are prefixed by a
#: terraform address in a plan, so the segment is found INSIDE the location and
#: the prefix before it is kept, which keeps two resources' rule 0 apart.
_DENY_RULE_SEGMENT = "].denyRule."
_EXCEPTION_PRINCIPALS = "exceptionPrincipals["


# -- CHECK A: public principals -----------------------------------------------


def check_public_principal(claim: Any, ctx: Any) -> Verdict:
    """Verdict for one ``public_principal`` claim.

    A *grant* of ``allUsers``/``allAuthenticatedUsers`` makes the resource
    world-readable (or worse) and is ``contradicted`` — this is the verdict that
    turns the worst silent pass into a block. The same member DENIED by an IAM
    *deny* policy is a guardrail and is ``grounded``; the same member EXCEPTED
    from that denial is its exact opposite — a public bypass of the guardrail —
    and is ``contradicted`` too. A claim carrying neither polarity, or a deny
    polarity without the denied/excepted discriminator, is not guessed at:
    ``deniedPrincipals`` and ``exceptionPrincipals`` are extracted through one
    branch, so a positive whose text asserts a denial would, without the
    discriminator, be stating the reverse of the truth half the time.
    """
    member = claim.value
    where = claim.location or "policy"
    fields = claim.fields() if hasattr(claim, "fields") else {}
    polarity = fields.get("polarity")
    if polarity == "deny":
        if "excepted" not in fields:
            logger.debug("%s: deny-polarity public_principal carries no excepted "
                         "discriminator — abstaining", where)
            return Verdict("unverified", "iam_public", member, 0,
                           f"{where}: this {member} claim comes from a deny policy "
                           f"but carries no 'excepted' discriminator — whether the "
                           f"rule denies {member} or exempts it from the denial was "
                           f"not decided")
        if fields["excepted"]:
            return Verdict("contradicted", "iam_public", member, 0,
                           f"{where}: this deny rule exempts {member} from the "
                           f"denial — a public exception is a bypass of the "
                           f"guardrail, not a guardrail")
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

    With NO role claim at all the check used to return nothing, which on an IAM
    allow policy reads as "no escalation was found" — see :func:`_no_role_claims`
    for the abstention that replaces the silence.
    """
    claims = tuple(getattr(ctx, "claims", ()) or ())
    roles = [c for c in claims if c.kind == "role"]
    if not roles:
        return _no_role_claims(ctx)
    members = [c for c in claims if c.kind in _MEMBER_KINDS]
    refused = [c for c in claims if c.kind == "unmodelled_principal"]
    verdicts: list[Verdict] = []
    for claim in roles:
        verdict = _escalation_verdict(claim, members, refused, ctx)
        if verdict is not None:
            verdicts.append(verdict)
    return verdicts


def _no_role_claims(ctx: Any) -> list[Verdict]:
    """The abstention for an IAM allow policy from which no role was extracted.

    The complement to preflight's zero-claims honesty, on this channel: a
    document whose bindings were present but whose roles the conservative
    extractor skipped (a non-string role, a binding that is not an object) would
    otherwise leave the escalation check silent, and silence on the channel that
    owns escalation reads as a clean pass.

    An EMPTY allow policy is the one honest silence, and ``getIamPolicy``
    spells it two ways: ``bindings: []`` and, for a policy that never had one,
    no ``bindings`` key at all — which is why the key is read with an explicit
    ``absent`` default here rather than being abstained on
    (:func:`gcp_grounding.preflight._legitimately_empty` says the same thing
    about the same two documents). A default never excuses a wrong TYPE, so a
    ``bindings`` that is present and is not a list still abstains.
    """
    if getattr(ctx, "document_kind", None) not in _ROLE_BEARING_KINDS:
        return []
    source = getattr(ctx, "source", None) or "policy"
    what = f"IAM allow policy {source}"
    try:
        bindings = evidence.scalar(ctx.document, "bindings", what=what,
                                   type=list, absent=[])
    except evidence.NotEvaluated as exc:
        return [Verdict("unverified", "iam_escalation", source, 0,
                        f"{source}: detected an IAM allow policy, but it {exc.reason} "
                        f"— no role was read from it, so no escalation class was "
                        f"decided")]
    evidence.examined(len(bindings), what=what)
    if not bindings:
        return []
    return [Verdict("unverified", "iam_escalation", source, 0,
                    f"{source}: {len(bindings)} binding(s) were present but no role "
                    f"claim was extracted from any of them — escalation classes were "
                    f"not decided for this document")]


def _escalation_verdict(claim: Any, members: list[Any], refused: list[Any],
                        ctx: Any) -> Verdict | None:
    snapshot = ctx.snapshot
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

    # THE PERMISSION SET, THROUGH THE EVIDENCE CHANNEL. The fetch path always
    # writes `included_permissions` and defaults it to `[]`, so a key-presence
    # test let a role whose permissions were NEVER CAPTURED intersect the
    # curated table emptily and return no verdict at all. An absent key and a
    # present-but-empty list are the same fact here — nothing was captured — so
    # both take the abstention below.
    what = f"the snapshot's record for {role}"
    try:
        record = evidence.scalar(snapshot.roles, role, what=what, type=dict)
        # `GcpSnapshot.from_dict` normalizes a captured permission set to a
        # sorted tuple, so `tuple` is the shape the contract guarantees and any
        # other is unread rather than empty. The count goes on the ledger
        # through `examined` because this arrives down a snapshot accessor, not
        # as a document read.
        permissions = evidence.scalar(record, "included_permissions",
                                      what=what, type=tuple)
    except evidence.NotEvaluated as exc:
        return _uncaptured_permissions(where, role, exc.reason)
    evidence.examined(len(permissions), what=what)
    if not permissions:
        return _uncaptured_permissions(
            where, role, "has an 'included_permissions' that is present and holds "
                         "no permissions")

    hits = _hits(role, permissions)
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
        return _no_usable_members(where, role, key, rendered, refused, ctx)
    return Verdict("grounded", "iam_escalation", role, 0,
                   f"{where}: warning — {role} grants {rendered} to "
                   f"{_capped(c.value for c in bound)}; review the principal")


def _uncaptured_permissions(where: str, role: str, observation: str) -> Verdict:
    """The abstention for a role captured WITHOUT its permission set.

    One message for both readings, because they are the same defect: the key is
    absent, or it is present and empty. Either way the intersection against the
    curated table is empty for want of data, not for want of escalation paths.
    """
    return Verdict("unverified", "iam_escalation", role, 0,
                   f"{where}: the snapshot captured {role} but not its "
                   f"included_permissions (it {observation}) — an uncaptured "
                   f"permission set intersects the escalation table emptily, so "
                   f"escalation classes were not decided")


def _no_usable_members(where: str, role: str, key: str, rendered: str,
                       refused: list[Any], ctx: Any) -> Verdict:
    """The verdict for an escalating role paired with NO member claim.

    Three causes, and the branch that used to ground over all three is split by
    cause here:

    - members existed but the extractor deliberately refused to model them (a
      federated wildcard, a deleted principal, a non-string) — an
      ``unmodelled_principal`` claim under the same binding key, which the
      caller already holds. Whether the grantee is public is UNDECIDED.
    - the binding's ``members`` key is ABSENT or unreadable — never captured,
      so the read raises and the abstention names what it could not read.
    - the list is PRESENT and observed empty — the one reading under which
      "there is nothing to grant to" is a fact rather than a hole.
    """
    unmodelled = [c for c in refused if c.location.startswith(f"{key}.")]
    if unmodelled:
        return Verdict("unverified", "iam_escalation", role, 0,
                       f"{where}: {role} grants {rendered}, and this binding's "
                       f"member(s) {_capped(c.value for c in unmodelled)} could not "
                       f"be modelled as principals — {_UNDECIDED_GRANTEE}")
    what = f"IAM binding {key}"
    try:
        listed = _binding_members(key, ctx.document, what)
    except evidence.NotEvaluated as exc:
        return Verdict("unverified", "iam_escalation", role, 0,
                       f"{where}: {role} grants {rendered}, but this binding "
                       f"{exc.reason} — {_UNDECIDED_GRANTEE}")
    if listed is None:
        return Verdict("unverified", "iam_escalation", role, 0,
                       f"{where}: {role} grants {rendered}, but this binding's "
                       f"members could not be located in the document — "
                       f"{_UNDECIDED_GRANTEE}")
    if listed:
        return Verdict("unverified", "iam_escalation", role, 0,
                       f"{where}: {role} grants {rendered}, and this binding lists "
                       f"{len(listed)} member(s) of which none was modelled — "
                       f"{_UNDECIDED_GRANTEE}")
    return Verdict("grounded", "iam_escalation", role, 0,
                   f"{where}: warning — {role} grants {rendered}, but this binding's "
                   f"members list is present and was observed empty, so there is "
                   f"nothing to grant to; review the binding")


def _binding_members(key: str, document: Any, what: str) -> tuple | None:
    """The ``members`` list of the binding at *key*, or None when *key* is not a
    document index into ``bindings`` (a terraform-anchored binding has no such
    index, and its members live wherever its resource put them).

    Both reads go through :mod:`~gcp_grounding.evidence`, so an absent or
    wrong-typed ``bindings``/``members`` raises instead of folding to "no
    members" — which is the whole distinction this function exists to preserve.
    """
    match = _BINDING_PREFIX.match(key)
    if match is None:
        return None
    bindings = evidence.rows(document, "bindings", what=what)
    index = int(match.group(1))
    if index >= len(bindings):
        return None
    binding = bindings[index]
    if not isinstance(binding, Mapping):
        return None
    return evidence.rows(binding, "members", what=what)


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
    nullified = _exception_defect(claim, ctx)
    if nullified is not None:
        status, detail = nullified
        return Verdict(status, "iam_escalation", normalized, 0,
                       f"{where}: this rule denies {normalized} "
                       f"({escalation_class}), but {detail} — so it was not shown "
                       f"to block that escalation path")
    return Verdict("grounded", "iam_escalation", normalized, 0,
                   f"{where}: denying {normalized} ({escalation_class}) blocks a "
                   f"known escalation path")


def _exception_defect(claim: Any, ctx: Any) -> tuple[str, str] | None:
    """Why this rule may not be reported as a working guardrail — or None.

    The deny claim's ``rule_index`` payload is documented as being for exactly
    this correlation and went unread: a rule whose EXCEPTION principals include
    a public member denies nobody, and a rule whose exceptions the gate cannot
    enumerate has an unknown reach. A universal exemption is a NULLIFIED
    guardrail, so ``contradicted``; an unclassifiable one is ``unverified``
    naming the member. No positive is emitted while any principal exception in
    the same rule is unexamined — including when there is no index to correlate
    on at all.
    """
    prefix = _rule_prefix(claim)
    if prefix is None:
        return ("unverified",
                "it carries no rule index, so the principals it exempts from the "
                "denial could not be correlated with it")
    siblings = [c for c in tuple(getattr(ctx, "claims", ()) or ())
                if isinstance(c.location, str)
                and c.location.startswith(prefix + _EXCEPTION_PRINCIPALS)]
    public = [c.value for c in siblings
              if c.kind == "public_principal" or c.value in PUBLIC_PRINCIPALS]
    if public:
        return ("contradicted",
                f"it exempts {_capped(public)} from that denial — an exemption "
                f"naming the public applies the rule to nobody")
    unclassified = [c.value for c in siblings if c.kind == "unmodelled_principal"]
    if unclassified:
        return ("unverified",
                f"it exempts {_capped(unclassified)}, which the gate cannot "
                f"enumerate, so how far the denial reaches is unknown")
    return None


def _rule_prefix(claim: Any) -> str | None:
    """The location prefix shared by every claim of this claim's deny rule.

    Built from the ``rule_index`` payload rather than from the location alone,
    so it is the documented discriminator that does the correlating; None when
    the claim carries no usable index or its own location does not sit inside
    the rule that index names.
    """
    fields = claim.fields() if hasattr(claim, "fields") else {}
    index = fields.get("rule_index")
    if isinstance(index, bool) or not isinstance(index, int):
        return None
    segment = f"rules[{index}{_DENY_RULE_SEGMENT}"
    location = claim.location if isinstance(claim.location, str) else ""
    head, found, _tail = location.partition(segment)
    if not found:
        return None
    return head + segment


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
