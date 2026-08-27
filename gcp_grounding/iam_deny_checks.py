"""The allow×deny interaction: masked grants, threaded exceptions, woken grants.

GCP evaluates IAM v2 deny policies BEFORE allow policies: a permission covered
by an applicable deny rule is unusable however many roles grant it. Three
consequences, each previously invisible to the gate, are decided here under one
verdict kind (:data:`KIND` — masked and woken are the two directions of the
same interaction, and one kind is one CLI seat, one drift identity family, one
grep):

- a fully covered grant LANDS (the setIamPolicy succeeds) but is INERT — a
  masked grant is not an exposure, so it is a **warning riding on a
  ``grounded`` verdict** (the :mod:`~gcp_grounding.iam_scope` polarity
  doctrine: blocking would block a safe state, and consequence for specific
  permissions belongs to the promise layer);
- a grant that ESCAPES a deny rule via an exception threads the guardrail the
  operator believes exists — a warning, EXCEPT when the escaping member is
  public, which is the guardrail nullified from the allow side and
  ``contradicted`` (the polarity mirror of
  ``iam_checks._exception_defect``'s public-exemption arm);
- removing or narrowing a deny rule can WAKE a dormant grant — effective
  permissions increase with no allow-policy edit anywhere. A woken pair whose
  permission is escalation-class or whose member is public is
  ``contradicted`` (a guardrail removal making a live path reachable — the
  firewall-widening polarity); an ordinary woken pair is a warning on
  ``grounded``.

FOUR RUN SHAPES. :func:`check_deny_shadow_plan` (C1) pairs a plan's own
bindings with the same plan's ``google_iam_deny_policy`` resources;
:func:`check_deny_shadow_estate` (C2) pairs a grant proposal (an ``iam_policy``
document or a plan's bindings) with the captured
``snapshot.iam_deny_policies`` table; :func:`check_deny_wake_plan` (C3) reads a
plan's ``resource_changes`` for a deleted/updated deny policy and computes the
woken set ``covered_old \\ covered_new`` over the estate's captured grants;
:func:`check_deny_pair` (C4) is the REST spelling of the same arc, the
document under review being the NEW deny policy and ``ctx.baseline`` the OLD.

**Set arithmetic, not z3 — decided.** The firewall shadow needs z3 because its
domain is a 2^32×2^16 interval algebra; the deny domain's relevant universe is
the FINITE set of (member, permission) pairs the grant under review actually
names, each decided by exact string equality plus a small curated containment
table. z3 would add no deciding power and one failure mode (an ``unverified``
on every builtin-backend run). **No z3 anywhere** — the module behaves
identically on the ``z3`` and ``builtin`` solver backends, exactly as
:mod:`~gcp_grounding.iam_checks` and :mod:`~gcp_grounding.iam_scope` state the
same invariant, and the accompanying tests assert backend identity explicitly.
The woken computation is still a set difference — ``covered_old \\
covered_new`` over enumerable pairs with a tri-state membership, FALSE required
to be PROVEN.

THE TRI-STATE. ``covered(member, rule)`` composes (a) a curated v1→v2
principal translation (user:/serviceAccount:/group:/allUsers only — everything
else is UNDECIDED by name, because a wrong translation fabricates coverage in
one direction and escape in the other); (b) principal containment
(``public:all`` universal, exact equality, exact-subject disjointness, the
``projects/<number>`` set decided through the hierarchy alias index — the one
true prefix family; group sets and every uncurated shape UNDECIDED by name);
(c) the v2→v1 permission bridge through
``iam_deny._normalize_permission`` (the one normalizer, the safe direction);
(d) conditions — a rule with a ``denialCondition`` can neither prove coverage
nor be ignored, so a would-be TRUE under one is UNDECIDED naming the
condition; (e) attachment containment — a deny policy governs a grant only
when its attachment point is the grant's project or an ancestor, resolved
through ``snapshot.resource_hierarchy``. While any exception of a rule is
unexamined, no positive coverage claim is made (``_exception_defect``'s
stance, inherited).

SOUNDNESS REGISTRATION — a recorded DEVIATION from the design's §5.
:func:`check_deny_shadow_plan` is registered ``subset_safe`` on ``"roles"`` at
import time (the ``tf_schema_checks`` pattern). C2, C3 and C4 SELF-GATE
through ``require_complete`` instead of being registered with their
categories: ``registry.run_document_checks``' gate is document-kind-blind, so
a ``requires_complete`` registration naming ``iam_deny_policies`` or
``iam_bindings`` would put one ``estate:incomplete`` verdict on EVERY run of
EVERY family — firewall edits, empty policies, org-policy documents — which is
the abstention flood the sec_rules docstring forbids. The self-gate keeps the
design's honesty where it means something: a GRANT-BEARING IAM proposal over
an uncaptured deny table gets the one ``estate:incomplete`` abstention saying
the interaction was not decided, and a clean "wakes nothing" is only ever
stated over a complete ``iam_bindings`` view — witness findings stand on a
partial view; only a clean answer needs the whole table.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Mapping

from . import evidence, iam_deny
from .claims import PUBLIC_PRINCIPALS
from .core.log import get_logger
from .core.report import Verdict
from .iam_checks import ESCALATION_PERMISSIONS, _capped
from .knowledge import UNKNOWN

logger = get_logger(__name__)

__all__ = [
    "KIND", "DOCUMENT_CHECKS", "PAIR_CHECKS",
    "check_deny_shadow_plan", "check_deny_shadow_estate",
    "check_deny_wake_plan", "check_deny_pair",
]

#: The one verdict kind of the whole interaction family — a seat in the CLI
#: decision block's JUDGMENT taste.
KIND = "iam_deny_shadow"

#: The kind of the self-gate's coverage refusal. Spelled here rather than
#: imported from :mod:`gcp_grounding.registry` (whose ``ESTATE_INCOMPLETE`` it
#: matches byte-for-byte) so a stripped checkout keeps the same abstention.
ESTATE_INCOMPLETE = "estate:incomplete"

_TF_PLAN = "tf_plan"
_DENY_TYPE = "google_iam_deny_policy"
_CUSTOM_ROLE_TYPE = "google_project_iam_custom_role"

#: Binding-shaped plan resources whose grants this family correlates. A
#: ``google_*_iam_policy``'s ``policy_data`` grants are NOT correlated — they
#: abstain by name when the interaction is otherwise engaged (a recorded
#: narrowing of the design's C1: abstaining is conservative, silence is not).
_BINDING_TYPE = re.compile(r"^google_\w+_iam_(?:binding|member)$")
_POLICY_TYPE = re.compile(r"^google_\w+_iam_policy$")

#: The universal v2 principal set — every translated member is in it.
PUBLIC_ALL = "principalSet://goog/public:all"

#: The curated v1→v2 translation, versioned with the code, deliberately
#: conservative (an ``ESCALATION_PERMISSIONS``-style constant): everything
#: outside it — ``domain:…``, ``deleted:…``, ``allAuthenticatedUsers`` (no
#: single well-documented v2 equivalent in the curated set), workforce/workload
#: pools, unknown prefixes — is UNDECIDED by name, never guessed.
_V2_PREFIXES = (
    ("user:", "principal://goog/subject/{}"),
    ("serviceAccount:",
     "principal://iam.googleapis.com/projects/-/serviceAccounts/{}"),
    ("group:", "principalSet://goog/group/{}"),
)
_V2_EXACT = {"allUsers": PUBLIC_ALL}

#: The one true string-PREFIX containment family: all identities in a project,
#: decidable through the hierarchy alias index for a project-local service
#: account. Everything else curated is exact-or-universal.
_PROJECT_SET = re.compile(
    r"^principalSet://cloudresourcemanager\.googleapis\.com/"
    r"projects/(?P<number>\d+)$")
_SA_EMAIL = re.compile(
    r"^[^@]+@(?P<project>[a-z][a-z0-9-]*)\.iam\.gserviceaccount\.com$")
_GROUP_SET = "principalSet://goog/group/"

#: The hierarchy node kinds an attachment point may decode to.
_NODE_PREFIXES = ("projects/", "folders/", "organizations/")

#: How an ``iam_bindings`` table key names its node: the CRM full resource
#: name, ``//cloudresourcemanager.googleapis.com/projects/acme-prod``.
_RESOURCE_NAME = re.compile(r"^//[a-z.]+/(?P<node>.+)$")


# -- tri-state plumbing --------------------------------------------------------


@dataclass(frozen=True)
class _Tri:
    """One three-valued answer: ``yes`` / ``no`` / ``undecided`` + the reason."""

    state: str
    reason: str = ""


_YES = _Tri("yes")
_NO = _Tri("no")


def _undecided(reason: str) -> _Tri:
    return _Tri("undecided", reason)


# -- the curated principal algebra --------------------------------------------


def _translate(member: str) -> tuple[str | None, str]:
    """The curated v2 spelling of a v1 grant member, or ``(None, why)``."""
    if member in _V2_EXACT:
        return _V2_EXACT[member], ""
    for prefix, template in _V2_PREFIXES:
        if member.startswith(prefix) and len(member) > len(prefix):
            return template.format(member[len(prefix):]), ""
    return None, (f"member {member!r} has no curated v2 spelling — a guessed "
                  f"translation fabricates coverage in one direction and "
                  f"escape in the other")


def _member_in(member_v1: str, member_v2: str, spelling: str,
               snapshot: Any) -> _Tri:
    """``member ∈ spelling`` — string-prefix encodable where it is decidable
    at all, UNDECIDED by name everywhere else."""
    if spelling == PUBLIC_ALL:
        return _YES  # the universal set covers every translated member
    if spelling == member_v2:
        return _YES
    if spelling.startswith("principal://") and member_v2.startswith("principal://"):
        return _NO  # exact subjects are disjoint
    matched = _PROJECT_SET.match(spelling)
    if matched is not None:
        return _project_set_member(member_v1, matched.group("number"), spelling,
                                   snapshot)
    if spelling.startswith(_GROUP_SET):
        return _Tri("undecided", f"group membership of {member_v1!r} in {spelling!r} is not captured in any snapshot category")
    return _undecided(f"the principal set {spelling!r} is outside the curated "
                      f"containment table")


def _project_set_member(member_v1: str, number: str, spelling: str,
                        snapshot: Any) -> _Tri:
    """Membership in the all-identities-in-a-project set: decidable for a
    project-local service account whose project the captured hierarchy maps to
    a number; UNDECIDED naming what is missing otherwise."""
    if not member_v1.startswith("serviceAccount:"):
        return _undecided(f"whether {member_v1!r} is an identity of the "
                          f"project set {spelling!r} is not decidable from "
                          f"its spelling")
    email = member_v1[len("serviceAccount:"):]
    matched = _SA_EMAIL.match(email)
    if matched is None:
        return _undecided(f"the service account email {email!r} does not "
                          f"parse as a project-local one, so its project "
                          f"cannot be compared with {spelling!r}")
    node = snapshot.hierarchy_node(f"projects/{matched.group('project')}")
    if node is UNKNOWN:
        return _undecided("the snapshot did not capture resource_hierarchy, "
                          f"so the project number behind {spelling!r} is "
                          "unknown")
    if node is None:
        return _undecided(f"projects/{matched.group('project')} is not in the "
                          f"captured hierarchy, so it cannot be compared with "
                          f"{spelling!r}")
    captured = node.get("number")
    if not captured:
        return _undecided(f"the captured hierarchy record for "
                          f"projects/{matched.group('project')} carries no "
                          f"project number")
    return _YES if str(captured) == number else _NO


# -- one deny rule, normalized -------------------------------------------------


@dataclass(frozen=True)
class _DenyRule:
    """One rule's coverage inputs, normalized once."""

    index: int
    denied_principals: tuple
    exception_principals: tuple
    #: Effective normalized short forms: denied − excepted.
    effective: frozenset
    #: Denied-side raw permissions with no unambiguous normalized form.
    unnormalizable_denied: tuple
    #: Exception-side raw permissions with no unambiguous normalized form — a
    #: wildcard here could claw back anything, so membership is undecidable.
    unnormalizable_excepted: tuple
    #: ``none`` / ``present`` / ``unreadable``.
    condition_state: str
    condition: str = ""


def _normalized_rule(index: int, fields: Mapping[str, tuple],
                     condition_state: str, condition: str) -> _DenyRule:
    excepted_norm: set = set()
    unnorm_exc: list = []
    for permission in fields["exception_permissions"]:
        normalized = iam_deny._normalize_permission(permission)
        if normalized is None:
            unnorm_exc.append(permission)
        else:
            excepted_norm.add(normalized)
    effective: list = []
    unnorm_denied: list = []
    for permission in fields["denied_permissions"]:
        normalized = iam_deny._normalize_permission(permission)
        if normalized is None:
            unnorm_denied.append(permission)
        elif normalized not in excepted_norm:
            effective.append(normalized)
    return _DenyRule(
        index=index,
        denied_principals=fields["denied_principals"],
        exception_principals=fields["exception_principals"],
        effective=frozenset(effective),
        unnormalizable_denied=tuple(unnorm_denied),
        unnormalizable_excepted=tuple(unnorm_exc),
        condition_state=condition_state,
        condition=condition,
    )


#: canonical camelCase field → the normalized key `_normalized_rule` reads.
_FIELD_KEYS = {
    "deniedPrincipals": "denied_principals",
    "exceptionPrincipals": "exception_principals",
    "deniedPermissions": "denied_permissions",
    "exceptionPermissions": "exception_permissions",
}


def _document_rules(container: Mapping[str, Any],
                    where: str) -> tuple[list, list]:
    """→ ``(rules, problems)`` from a deny document / plan block / ``change``
    side, through the claims module's own field walkers (no second parser of
    the spellings). A rule that cannot be read whole becomes a PROBLEM string
    — the caller's named abstention — never a partial rule: a rule read half
    is coverage guessed at."""
    problems: list = []
    rules_raw = container.get("rules")
    if rules_raw is None:
        rules_raw = []
    if not isinstance(rules_raw, list):
        return [], [f"{where}: carries no readable 'rules' list "
                    f"({type(rules_raw).__name__}) — what it denies was not "
                    f"read"]
    out: list = []
    for index, rule in enumerate(rules_raw):
        deny_rule = (iam_deny._as_mapping(
            iam_deny._get(rule, iam_deny._DENY_RULE_KEYS))
            if isinstance(rule, Mapping) else None)
        if deny_rule is None:
            problems.append(f"{where}: rules[{index}] carries no readable "
                            f"denyRule object — what it denies was not read")
            continue
        fields: dict = {}
        broken = False
        for canonical, spellings, _flag in (*iam_deny._PRINCIPAL_FIELDS,
                                            *iam_deny._PERMISSION_FIELDS):
            raw = iam_deny._get(deny_rule, spellings)
            entries = raw if isinstance(raw, list) else ([] if raw is None
                                                         else None)
            if entries is None or any(not isinstance(e, str) or not e
                                      for e in entries):
                problems.append(
                    f"{where}: rules[{index}].{canonical} is not a list of "
                    f"plain strings — the rule's reach was not read")
                broken = True
                break
            fields[_FIELD_KEYS[canonical]] = tuple(entries)
        if broken:
            continue
        state, condition = _condition_state(deny_rule)
        out.append(_normalized_rule(index, fields, state, condition))
    return out, problems


def _condition_state(deny_rule: Mapping[str, Any]) -> tuple[str, str]:
    raw = iam_deny._get(deny_rule, iam_deny._DENIAL_CONDITION_KEYS)
    if raw is None:
        return "none", ""
    block = iam_deny._as_mapping(raw)
    expression = block.get("expression") if block is not None else None
    if isinstance(expression, str) and expression.strip():
        return "present", expression
    return "unreadable", ""


def _estate_rules(record: Mapping[str, Any]) -> list:
    """The normalized rules of one ``iam_deny_policies`` record — already
    validated by :func:`gcp_grounding.knowledge._parse_iam_deny_policies`, so
    this only re-keys."""
    out: list = []
    # the parser writes 'rules' and all four list fields on every record, so
    # the direct reads below cannot invent emptiness for a value nobody read
    for index, rule in enumerate(record["rules"]):
        fields = {key: tuple(rule[key])
                  for key in ("denied_principals", "exception_principals",
                              "denied_permissions", "exception_permissions")}
        condition = rule.get("denial_condition")
        if isinstance(condition, Mapping):
            state, text = "present", str(condition.get("expression"))
        else:
            state, text = "none", ""
        out.append(_normalized_rule(index, fields, state, text))
    return out


# -- the coverage tri-state ----------------------------------------------------


def _names_permission(rule: _DenyRule, permission: str) -> _Tri:
    """Is *permission* (v1 short form) in the rule's effective denied set?"""
    if rule.unnormalizable_excepted:
        return _undecided(
            f"exception permission(s) {_capped(map(repr, rule.unnormalizable_excepted))} "
            f"have no unambiguous normalized form, so what the rule still "
            f"denies is not decidable")
    if permission in rule.effective:
        return _YES
    if rule.unnormalizable_denied:
        return _undecided(
            f"denied permission(s) {_capped(map(repr, rule.unnormalizable_denied))} "
            f"have no unambiguous normalized form, so whether the rule names "
            f"{permission} is not decidable")
    return _NO


def _principal_coverage(member: str, rule: _DenyRule,
                        snapshot: Any) -> tuple[str, str]:
    """→ one of ``covered`` / ``clear`` / ``escapes`` / ``undecided`` (+why)
    for the PRINCIPAL half of one rule, in Kleene logic: TRUE requires
    membership in the denied set AND proven non-membership in EVERY exception;
    any UNDECIDED on the deciding side propagates with its reason."""
    member_v2, why = _translate(member)
    if member_v2 is None:
        return "undecided", why
    in_denied, reason = "no", ""
    for spelling in rule.denied_principals:
        tri = _member_in(member, member_v2, spelling, snapshot)
        if tri.state == "yes":
            in_denied = "yes"
            break
        if tri.state == "undecided" and in_denied == "no":
            in_denied, reason = "undecided", tri.reason
    if in_denied == "no":
        return "clear", ""
    if in_denied == "undecided":
        return "undecided", reason
    for spelling in rule.exception_principals:
        tri = _member_in(member, member_v2, spelling, snapshot)
        if tri.state == "yes":
            return "escapes", spelling
        if tri.state == "undecided":
            return "undecided", (f"the exception {spelling!r} was not "
                                 f"decided ({tri.reason}) — while any "
                                 f"exception of the rule is unexamined, no "
                                 f"positive coverage claim is made")
    return "covered", ""


def _covered(member: str, rule: _DenyRule, snapshot: Any) -> tuple[str, str]:
    """The full member×rule tri-state: the principal half, then the condition
    guard — a rule with a ``denialCondition`` can neither prove coverage (it
    may be false at request time) nor be ignored (it may be true), so a
    would-be ``covered`` is UNDECIDED naming the condition and ``clear`` stays
    ``clear`` — conservative in both directions."""
    state, detail = _principal_coverage(member, rule, snapshot)
    if state == "covered" and rule.condition_state == "present":
        return "undecided", (f"covered only under condition "
                             f"{rule.condition!r} — request-time truth is not "
                             f"decidable offline")
    if state == "covered" and rule.condition_state == "unreadable":
        return "undecided", ("the rule's denialCondition block is present "
                             "but unreadable — an unread condition can "
                             "neither prove nor waive coverage")
    return state, detail


# -- attachment containment ----------------------------------------------------


def _attachment_node(parent: Any) -> tuple[str | None, str]:
    """The decoded attachment node of a deny policy's ``parent`` attribute (or
    a REST ``name``'s middle segment), or ``(None, why)``."""
    if not isinstance(parent, str) or not parent:
        return None, "the deny policy names no readable attachment parent"
    decoded = urllib.parse.unquote(parent)
    if "/" in decoded and not decoded.startswith(_NODE_PREFIXES):
        decoded = decoded.split("/", 1)[1]
    if decoded.startswith(_NODE_PREFIXES):
        return decoded, ""
    return None, (f"the attachment parent {parent!r} does not decode to a "
                  f"projects/, folders/ or organizations/ node")


def _policy_name_node(document: Mapping[str, Any]) -> tuple[str | None, str]:
    """The attachment node encoded in a REST deny policy's own ``name``
    (``policies/<encoded-parent>/denypolicies/<id>``)."""
    name = document.get("name")
    if not isinstance(name, str) or not name:
        return None, "the deny policy carries no readable 'name'"
    segments = name.split("/")
    if (len(segments) != 4 or segments[0] != "policies"
            or segments[2] != "denypolicies"):
        return None, (f"the deny policy name {name!r} is not "
                      f"'policies/<encoded-parent>/denypolicies/<id>', so its "
                      f"attachment point was not decoded")
    return _attachment_node(segments[1])


def _governs(node: str, project: str, snapshot: Any) -> _Tri:
    """Does a deny policy attached at *node* govern a grant at
    ``projects/<project>``? Equality decides; ancestry is resolved through the
    captured hierarchy's parent chain; anything off the captured tree is
    UNDECIDED by name."""
    if not project:
        return _undecided("the grant names no readable project, so whether "
                          f"the deny policy attached at {node!r} governs it "
                          "was not decided")
    current = f"projects/{project}"
    if node == current:
        return _YES
    seen = {current}
    while True:
        record = snapshot.hierarchy_node(current)
        if record is UNKNOWN:
            return _undecided("the snapshot did not capture "
                              "resource_hierarchy, so whether the deny "
                              f"policy attached at {node!r} governs "
                              f"projects/{project} was not decided")
        if record is None:
            return _undecided(f"{current} is not in the captured hierarchy, "
                              f"so the containment walk from "
                              f"projects/{project} to {node!r} was not "
                              f"decided")
        parent = record.get("parent")
        if parent is None:
            return _NO
        if not isinstance(parent, str) or parent in seen:
            return _undecided(f"the captured hierarchy above "
                              f"projects/{project} is not a readable chain — "
                              f"the containment walk was not decided")
        if parent == node:
            return _YES
        seen.add(parent)
        current = parent


def _binding_key_node(key: str) -> str | None:
    """The hierarchy node an ``iam_bindings`` table key names, or None."""
    matched = _RESOURCE_NAME.match(key)
    if matched is None:
        return None
    node = matched.group("node")
    return node if node.startswith(_NODE_PREFIXES) else None


def _within(grant_node: str, node: str, snapshot: Any) -> _Tri:
    """Is *grant_node* at or below the attachment *node*?"""
    if grant_node == node:
        return _YES
    if not grant_node.startswith("projects/"):
        # folder/organization-level grants: decided only by equality — walking
        # arbitrary node kinds is postponed with the estate tier (E-1).
        return _undecided(f"the grant at {grant_node!r} is not project-scoped "
                          f"— its containment under {node!r} was not decided")
    return _governs(node, grant_node[len("projects/"):], snapshot)


# -- grants --------------------------------------------------------------------


@dataclass(frozen=True)
class _Grant:
    where: str
    role: str
    members: tuple
    project: str = ""
    conditional: bool = False


def _google_resources(document: Mapping[str, Any]
                      ) -> Iterator[tuple[str, str, Any]]:
    """``tf_claims``' OWN plan walker, resolved lazily so a checkout without
    the terraform extractor keeps these checks silent instead of broken."""
    try:
        from . import tf_claims
    except ImportError:
        logger.debug("tf_claims is not part of this checkout — the deny "
                     "shadow has no plan walker and stays silent")
        return
    yield from tf_claims._google_resources(document)


def _plan_grants(resources: Iterable[tuple]) -> tuple[list, list]:
    """→ ``(grants, problems)`` from a plan's binding-shaped resources."""
    grants: list = []
    problems: list = []
    for address, rtype, values in resources:
        if _POLICY_TYPE.match(rtype):
            problems.append(f"{address}: a *_iam_policy resource's policy_data "
                            f"grants were not correlated with the deny "
                            f"policies — the allow×deny interaction was not "
                            f"decided for it")
            continue
        if not _BINDING_TYPE.match(rtype):
            continue
        if not isinstance(values, Mapping):
            problems.append(f"{address}: this binding has no readable planned "
                            f"values — the allow×deny interaction was not "
                            f"decided for it")
            continue
        meta = next((m for m in ("count", "for_each") if m in values), None)
        if meta is not None:
            problems.append(f"{address}: carries {meta!r}, so how many "
                            f"instances the block creates is not decided — "
                            f"the allow×deny interaction was not decided for "
                            f"it")
            continue
        role = values.get("role")
        raw_members = values.get("members", values.get("member"))
        members = raw_members if isinstance(raw_members, list) \
            else [raw_members] if isinstance(raw_members, str) else None
        if (not isinstance(role, str) or not role or members is None
                or any(not isinstance(m, str) or not m for m in members)):
            problems.append(f"{address}: this binding's role or members could "
                            f"not be read as plain strings — the allow×deny "
                            f"interaction was not decided for it")
            continue
        project = values.get("project")
        project = project if isinstance(project, str) else ""
        conditional = bool(values.get("condition"))
        grants.append(_Grant(where=address, role=role, members=tuple(members),
                             project=project, conditional=conditional))
    return grants, problems


def _document_grants(document: Mapping[str, Any]) -> list:
    """The readable (role, members) grants of an ``iam_policy`` document.

    Unreadable binding shapes contribute nothing HERE — the IAM extractors and
    the zero-claims honesty guard already own the abstention for a malformed
    allow policy, and this check's only clean statement is silence anyway."""
    bindings = document.get("bindings")
    if not isinstance(bindings, list):
        return []
    grants: list = []
    for index, binding in enumerate(bindings):
        if not isinstance(binding, Mapping):
            continue
        role = binding.get("role")
        members = binding.get("members")
        if (not isinstance(role, str) or not role
                or not isinstance(members, list) or not members
                or any(not isinstance(m, str) or not m for m in members)):
            continue
        grants.append(_Grant(where=f"bindings[{index}]", role=role,
                             members=tuple(members),
                             conditional=binding.get("condition") is not None))
    return grants


def _plan_custom_roles(resources: Iterable[tuple]) -> dict:
    """Full role name → its same-plan permission tuple (or None when the list
    is unreadable), for the one other sanctioned expansion source."""
    names: dict = {}
    for address, rtype, values in resources:
        if rtype != _CUSTOM_ROLE_TYPE or not isinstance(values, Mapping):
            continue
        role_id = values.get("role_id")
        project = values.get("project")
        if not (isinstance(role_id, str) and role_id
                and isinstance(project, str) and project):
            continue
        permissions = values.get("permissions")
        readable = (isinstance(permissions, list)
                    and all(isinstance(p, str) and p for p in permissions))
        names[f"projects/{project}/roles/{role_id}"] = (
            tuple(permissions) if readable else None)
    return names


def _role_permissions(snapshot: Any, role: str) -> tuple[tuple | None, str]:
    """*role*'s enumerated permission set, or ``(None, why)`` — mirroring
    ``iam_scope._enumerated``, including the absent-OR-empty
    ``included_permissions`` collapse: both mean nothing was captured, and an
    uncaptured set decides nothing. ``(None, "")`` is the one SILENT answer:
    a role the enumeration PROVES nonexistent grants no permissions, so there
    is no interaction to decide and the existence pass already owns the
    finding (the ``iam_checks._escalation_verdict`` precedent)."""
    exists = snapshot.role_exists(role)
    if exists is UNKNOWN:
        return None, ("the snapshot did not capture roles, so what the role "
                      "grants is unknown")
    if exists is False:
        logger.debug("deny shadow: %s is not in the snapshot — the existence "
                     "pass owns it; a nonexistent role grants nothing", role)
        return None, ""
    what = f"the snapshot's record for {role}"
    try:
        record = evidence.scalar(snapshot.roles, role, what=what, type=dict)
        permissions = evidence.scalar(record, "included_permissions",
                                      what=what, type=tuple)
    except evidence.NotEvaluated as exc:
        return None, (f"the snapshot captured {role} but {exc.reason} — an "
                      f"uncaptured permission set decides nothing")
    evidence.examined(len(permissions), what=what)
    if not permissions:
        return None, (f"the snapshot captured {role} with an "
                      f"included_permissions that is present and holds no "
                      f"permissions — nothing was captured, so nothing was "
                      f"decided")
    return permissions, ""


def _grant_permissions(grant: _Grant, custom_roles: Mapping[str, Any],
                       snapshot: Any) -> tuple[tuple | None, str]:
    """The grant's expanded permission set: the same-plan custom role's own
    list when the bound role is defined in the same proposal, else
    ``snapshot.roles`` — the two sources scenario 2 already sanctioned;
    anything else abstains by name, never guessed."""
    if grant.role in custom_roles:
        permissions = custom_roles[grant.role]
        if permissions is None:
            return None, (f"the same-plan custom role {grant.role} carries a "
                          f"'permissions' attribute that is not a list of "
                          f"plain names — its reach was not read")
        evidence.examined(len(permissions),
                          what=f"the same-plan custom role {grant.role}")
        return permissions, ""
    return _role_permissions(snapshot, grant.role)


# -- shared pair verdicts ------------------------------------------------------


def _classified(permission: str) -> str:
    escalation_class = ESCALATION_PERMISSIONS.get(permission)
    return (f"{permission} ({escalation_class})" if escalation_class
            else permission)


def _unverified(target: str, message: str) -> Verdict:
    return Verdict("unverified", KIND, target, 0, message)


def _interaction_verdicts(grant: _Grant, expanded: tuple, rules: Iterable,
                          node: str | None, node_why: str, deny_where: str,
                          snapshot: Any) -> list:
    """The masked / threaded / undecided verdicts for one grant against one
    deny policy's rules — the shared arc of C1 and C2. A CONDITIONAL grant
    whose permissions a rule names (or might name) abstains by name instead of
    being covered or cleared — its own reach is request-time dependent
    (ESC-DENY-ALLOW-CONDITIONS) — and a rule that names nothing the grant
    expands to says nothing, so the conditionality of an untouched grant stays
    quiet."""
    verdicts: list = []
    for rule in rules:
        named = sorted(p for p in set(expanded)
                       if _names_permission(rule, p).state == "yes")
        undecided_permission = next(
            (p for p in sorted(set(expanded))
             if _names_permission(rule, p).state == "undecided"), None)
        if not named and undecided_permission is None:
            continue  # this rule has nothing to say about this grant
        where = f"rule {rule.index} of {deny_where}"
        if grant.conditional:
            verdicts.append(_unverified(grant.role, (
                f"{grant.where}: {where} names permission(s) this grant may "
                f"carry, but the grant is conditional — its own reach is "
                f"request-time dependent, so the allow×deny interaction was "
                f"not decided (ESC-DENY-ALLOW-CONDITIONS)")))
            continue
        if undecided_permission is not None and not named:
            verdicts.append(_unverified(grant.role, (
                f"{grant.where}: whether {where} names any permission of "
                f"{grant.role} was not decided — "
                f"{_names_permission(rule, undecided_permission).reason}")))
            continue
        if node is None:
            verdicts.append(_unverified(grant.role, (
                f"{grant.where}: {where} names "
                f"{_capped(map(_classified, named))}, but {node_why} — "
                f"whether it governs this grant was not decided")))
            continue
        governs = _governs(node, grant.project, snapshot)
        if governs.state == "no":
            continue
        if governs.state == "undecided":
            verdicts.append(_unverified(grant.role, (
                f"{grant.where}: {where} names "
                f"{_capped(map(_classified, named))}, but {governs.reason}")))
            continue
        covered_members: list = []
        threading: list = []
        undecided_members: list = []
        for member in grant.members:
            state, detail = _covered(member, rule, snapshot)
            if state == "covered":
                covered_members.append(member)
            elif state == "escapes":
                threading.append((member, detail))
            elif state == "undecided":
                undecided_members.append((member, detail))
        rendered = _capped(_classified(p) for p in named)
        if covered_members:
            entire = set(named) == set(expanded)
            tail = (" — the entire grant is inert" if entire
                    else "; the rest of the grant is untouched")
            verdicts.append(Verdict(
                "grounded", KIND, grant.role, 0,
                f"{grant.where}: warning — {where} masks {rendered} granted "
                f"to {_capped(covered_members)}: the grant lands but is "
                f"inert{tail}; a masked grant is not an exposure, and "
                f"removing the deny rule would wake it"))
        for member, exception in threading:
            if member in PUBLIC_PRINCIPALS:
                verdicts.append(Verdict(
                    "contradicted", KIND, grant.role, 0,
                    f"{grant.where}: {member} threads the exception "
                    f"{exception!r} of {where} — a public grant threading a "
                    f"deny guardrail is the guardrail nullified from the "
                    f"allow side"))
            else:
                verdicts.append(Verdict(
                    "grounded", KIND, grant.role, 0,
                    f"{grant.where}: warning — this grant to {member} threads "
                    f"the exception {exception!r} of {where}, which names "
                    f"{rendered} — the guardrail does not cover it; review "
                    f"the exception"))
        for member, reason in undecided_members:
            verdicts.append(_unverified(grant.role, (
                f"{grant.where}: whether {where} covers {member} was not "
                f"decided — {reason}")))
    return verdicts


# -- C1: same-plan grants × same-plan deny policies ---------------------------


def check_deny_shadow_plan(ctx: Any) -> list:
    """The masked/threaded arcs INSIDE one terraform plan: both resource kinds
    in the same document, the role expanded through ``snapshot.roles`` or the
    same plan's own custom-role block. A plan with bindings and no deny
    resources, or vice versa, is honest silence — nothing interacts."""
    if getattr(ctx, "document_kind", None) != _TF_PLAN:
        return []
    document = getattr(ctx, "document", None)
    if not isinstance(document, Mapping):
        return []
    resources = list(_google_resources(document))
    denies = {address: values for address, rtype, values in resources
              if rtype == _DENY_TYPE}
    if not denies:
        return []
    grants, grant_problems = _plan_grants(resources)
    if not grants and not grant_problems:
        return []
    verdicts = [_unverified(problem.split(":", 1)[0], problem)
                for problem in grant_problems]
    custom_roles = _plan_custom_roles(resources)
    units: list = []
    for address in sorted(denies):
        values = denies[address]
        if not isinstance(values, Mapping):
            verdicts.append(_unverified(address, (
                f"{address}: this deny policy has no readable planned values "
                f"— the allow×deny interaction was not decided for it")))
            continue
        meta = next((m for m in ("count", "for_each") if m in values), None)
        if meta is not None:
            verdicts.append(_unverified(address, (
                f"{address}: carries {meta!r}, so how many deny policies the "
                f"block creates is not decided — the allow×deny interaction "
                f"was not decided for it")))
            continue
        rules, problems = _document_rules(values, address)
        verdicts.extend(_unverified(address, problem) for problem in problems)
        node, node_why = _attachment_node(values.get("parent"))
        units.append((address, rules, node, node_why))
    for grant in grants:
        expanded, why = _grant_permissions(grant, custom_roles, ctx.snapshot)
        if expanded is None:
            if why:
                verdicts.append(_unverified(grant.role, (
                    f"{grant.where}: {why} — the allow×deny interaction was "
                    f"not decided for this grant")))
            continue  # a provably nonexistent role grants nothing
        for address, rules, node, node_why in units:
            verdicts.extend(_interaction_verdicts(
                grant, expanded, rules, node, node_why, address,
                ctx.snapshot))
    return _deduplicated(verdicts)


# -- C2: a grant proposal × the estate deny table -----------------------------


def check_deny_shadow_estate(ctx: Any) -> list:
    """The same arcs against the ESTATE's captured ``iam_deny_policies``.

    SELF-GATED (see the module docstring): the check's silence on a pair reads
    downstream as "no guardrail interaction", and silence from a partial deny
    table is indistinguishable from silence from a complete one — so over an
    incomplete or uncaptured table the pairs are not computed and ONE
    ``estate:incomplete`` verdict puts "the allow×deny interaction was not
    decided" on the record of the grant-bearing run, which is strictly more
    honest than the old silent assumption that no deny policy exists."""
    kind = getattr(ctx, "document_kind", None)
    document = getattr(ctx, "document", None)
    if not isinstance(document, Mapping):
        return []
    custom_roles: Mapping[str, Any] = {}
    if kind == "iam_policy":
        grants = _document_grants(document)
    elif kind == _TF_PLAN:
        resources = list(_google_resources(document))
        if any(rtype == _DENY_TYPE for _a, rtype, _v in resources):
            # the plan proposes its own deny policies: the wake/mask arcs of
            # THIS plan are C1's and C3's; pairing its grants against the
            # estate table too would double-report every finding
            return []
        # C1 owns the plan-side unreadable-grant abstentions
        grants, _problems = _plan_grants(resources)
        custom_roles = _plan_custom_roles(resources)
    else:
        return []
    if not grants:
        return []
    reason = _require_complete(ctx.snapshot, "iam_deny_policies")
    table = getattr(ctx.snapshot, "iam_deny_policies", None)
    if reason is not None or not isinstance(table, Mapping):
        return _uncaptured_interaction(ctx, grants, custom_roles, reason)
    evidence.examined(len(table), what="the captured iam_deny_policies table")
    verdicts: list = []
    for name in sorted(table):
        record = table[name]
        rules = _estate_rules(record)
        node = record.get("attachment_point")
        for grant in grants:
            expanded, why = _grant_permissions(grant, custom_roles,
                                               ctx.snapshot)
            if expanded is None:
                if why:
                    verdicts.append(_unverified(grant.role, (
                        f"{grant.where}: {why} — the allow×deny interaction "
                        f"was not decided for this grant")))
                continue  # a provably nonexistent role grants nothing
            verdicts.extend(_interaction_verdicts(
                grant, expanded, rules, node, "", name, ctx.snapshot))
    return _deduplicated(verdicts)


def _uncaptured_interaction(ctx: Any, grants: list,
                            custom_roles: Mapping[str, Any],
                            reason: str | None) -> list:
    """The one abstention an UNCAPTURED (or incomplete) deny table earns —
    scoped, deliberately, to ESCALATION-MATERIAL grants.

    A recorded DEVIATION from the design's C2, measured before it was made:
    abstaining on EVERY grant-bearing run put one ``estate:incomplete``
    verdict on ~20 unrelated suites' reports and made the hook's
    abstain-notes channel chatter on every clean grant — the abstention flood
    the honesty channels exist to avoid. So the trigger is the same curation
    that decides blocking in :mod:`~gcp_grounding.iam_checks`: only a
    readable, unconditional grant whose expansion carries an
    :data:`ESCALATION_PERMISSIONS` entry — the permissions deny guardrails
    exist for — puts "the allow×deny interaction was not decided" on the
    record. Everything else keeps the pre-existing silence, recorded in the
    escalations register (ESC-DENY-FETCH-CAPTURE). The scoping applies ONLY
    to this uncaptured arm: a CAPTURED table pairs every grant."""
    material: list = []
    for grant in grants:
        if grant.conditional:
            continue
        expanded, _why = _grant_permissions(grant, custom_roles, ctx.snapshot)
        if expanded is None:
            continue
        hits = sorted(set(expanded) & set(ESCALATION_PERMISSIONS))
        if hits:
            material.append((grant, hits))
    if not material:
        return []
    rendered = _capped(f"{grant.role} ({_capped(hits)})"
                       for grant, hits in material)
    return [Verdict(
        "unverified", ESTATE_INCOMPLETE, "iam-deny-interaction", 0,
        f"this proposal grants escalation-class permission(s) — {rendered} — "
        f"and the current state did not capture 'iam_deny_policies' "
        f"({reason or 'the table could not be read from this snapshot'}), so "
        f"whether an estate deny policy masks those grants, or fails to "
        f"cover them, was not decided — the allow×deny interaction needs the "
        f"deny table")]


def _deduplicated(verdicts: list) -> list:
    """One copy of each identical verdict: a grant repeated against several
    policies can raise the same conditional/expansion abstention repeatedly."""
    seen: set = set()
    out: list = []
    for verdict in verdicts:
        key = (verdict.status, verdict.kind, verdict.target, verdict.message)
        if key not in seen:
            seen.add(key)
            out.append(verdict)
    return out


# -- the woken arc: C3 (plan) and C4 (REST pair) ------------------------------


def _pair_covered(member: str, permission: str, rules: Iterable,
                  snapshot: Any) -> tuple[str, str, int]:
    """``(state, reason, witness rule index)`` — is (member, permission)
    covered by ANY of *rules*? ``no`` must be PROVEN: any undecided rule that
    might name the permission makes the answer undecided."""
    undecided_reason = ""
    for rule in rules:
        names = _names_permission(rule, permission)
        if names.state == "no":
            continue
        state, detail = _covered(member, rule, snapshot)
        if names.state == "yes" and state == "covered":
            return "yes", "", rule.index
        if names.state == "undecided" or state == "undecided":
            undecided_reason = undecided_reason or (
                names.reason if names.state == "undecided" else detail)
    if undecided_reason:
        return "undecided", undecided_reason, -1
    return "no", "", -1


def _estate_grant_pairs(node: str, snapshot: Any) -> tuple[list, list]:
    """→ ``(pairs, undecided)`` — every (binding key, member, permission) the
    captured ``iam_bindings`` table grants within the attachment subtree of
    *node*, roles expanded through ``snapshot.roles``; every miss abstains
    per-binding by name."""
    pairs: list = []
    undecided: list = []
    table = snapshot.iam_bindings
    evidence.examined(len(table), what="the captured iam_bindings table")
    for key in sorted(table):
        grant_node = _binding_key_node(key)
        if grant_node is None:
            undecided.append(f"{key}: not a resource name whose node this "
                             f"check can place — its grants were not compared")
            continue
        tri = _within(grant_node, node, snapshot)
        if tri.state == "no":
            continue
        if tri.state == "undecided":
            undecided.append(f"{key}: {tri.reason}")
            continue
        # the iam_bindings parser writes the 'bindings' key on every record
        for binding in snapshot.iam_bindings[key]["bindings"]:
            if not isinstance(binding, Mapping):
                undecided.append(f"{key}: a binding record is not an object — "
                                 f"its grants were not compared")
                continue
            role = binding.get("role")
            members = binding.get("members")
            if (not isinstance(role, str) or not role
                    or not isinstance(members, (list, tuple))
                    or any(not isinstance(m, str) or not m for m in members)):
                undecided.append(f"{key}: a binding's role or members could "
                                 f"not be read — its grants were not compared")
                continue
            if binding.get("condition") not in (None, ""):
                undecided.append(
                    f"{key}: the grant of {role} is conditional — its own "
                    f"reach is request-time dependent, so whether it wakes "
                    f"was not decided (ESC-DENY-ALLOW-CONDITIONS)")
                continue
            permissions, why = _role_permissions(snapshot, role)
            if permissions is None:
                undecided.append(f"{key}: {why} — the grants of {role} were "
                                 f"not compared")
                continue
            for member in members:
                for permission in permissions:
                    pairs.append((key, member, permission))
    return pairs, undecided


def _wake_findings(old_rules: list, new_rules: list, node: str, where: str,
                   snapshot: Any, complete_reason: str | None) -> list:
    """The woken set of one deny change: pairs with ``covered_old = TRUE`` and
    ``covered_new = FALSE`` (FALSE proven — an UNDECIDED on either side
    abstains by name). The clean "wakes nothing" is stated only over a
    complete ``iam_bindings`` view (*complete_reason* is the caller's own
    ``require_complete`` answer); witness findings stand on a partial view."""
    bindings = getattr(snapshot, "iam_bindings", UNKNOWN)
    if bindings is UNKNOWN or bindings is None or not isinstance(bindings,
                                                                 Mapping):
        return [_unverified(where, (
            f"{where}: the snapshot did not capture iam_bindings — which "
            f"dormant grants this deny change wakes was not decided"))]
    if not bindings:
        evidence.emptiness_is_dispositive(
            "the captured iam_bindings table holds no grant records, so "
            "there is no grant this deny change could wake")
    pairs, undecided = _estate_grant_pairs(node, snapshot)
    verdicts: list = []
    woken = 0
    for key, member, permission in pairs:
        old_state, old_reason, old_rule = _pair_covered(member, permission,
                                                        old_rules, snapshot)
        if old_state == "no":
            continue
        new_state, new_reason, _r = _pair_covered(member, permission,
                                                  new_rules, snapshot)
        if old_state == "undecided" or new_state == "undecided":
            undecided.append(
                f"{key}: whether the change wakes the grant of {permission} "
                f"to {member} was not decided "
                f"({old_reason or new_reason})")
            continue
        if new_state == "yes":
            continue  # still covered — nothing woke
        woken += 1
        escalation_class = ESCALATION_PERMISSIONS.get(permission)
        public = member in PUBLIC_PRINCIPALS
        status = "contradicted" if (escalation_class or public) else "grounded"
        if status == "contradicted":
            verdicts.append(Verdict(
                "contradicted", KIND, where, 0,
                f"{where}: removing or narrowing rule {old_rule} wakes the "
                f"dormant grant of {_classified(permission)} to {member} "
                f"({key}) — the deny policy was the only thing keeping a "
                f"known escalation path inert"))
        else:
            verdicts.append(Verdict(
                "grounded", KIND, where, 0,
                f"{where}: warning — removing or narrowing rule {old_rule} "
                f"wakes the dormant grant of {permission} to {member} "
                f"({key}); the removal may be intended — consequence for "
                f"specific permissions belongs to the promise layer"))
    for reason in sorted(set(undecided)):
        verdicts.append(_unverified(where, f"{where}: {reason}"))
    if not verdicts and not woken:
        if complete_reason is not None:
            return [_unverified(where, (
                f"{where}: no woken grant was found, but a clean 'wakes "
                f"nothing' needs the whole grant population: "
                f"{complete_reason}"))]
        verdicts.append(Verdict(
            "grounded", KIND, where, 0,
            f"{where}: no dormant grant wakes — every captured grant under "
            f"{node} was compared against the old and new rule sets"))
    return verdicts


def check_deny_wake_plan(ctx: Any) -> list:
    """C3 — a plan deleting or updating a ``google_iam_deny_policy``: old
    coverage from ``change.before``, new from ``change.after`` (a delete's
    ``after`` is the empty policy). A deny deletion must never pass silently:
    an unreadable old side abstains naming the address."""
    if getattr(ctx, "document_kind", None) != _TF_PLAN:
        return []
    document = getattr(ctx, "document", None)
    if not isinstance(document, Mapping):
        return []
    changes = document.get("resource_changes")
    if not isinstance(changes, list):
        return []
    verdicts: list = []
    for entry in changes:
        if not isinstance(entry, Mapping) or entry.get("type") != _DENY_TYPE:
            continue
        change = entry.get("change")
        actions = change.get("actions") if isinstance(change, Mapping) else None
        if not isinstance(actions, list) or not {"delete", "update"} & set(
                map(str, actions)):
            continue
        address = str(entry.get("address") or "<google_iam_deny_policy>")
        before = change.get("before")
        if not isinstance(before, Mapping):
            verdicts.append(_unverified(address, (
                f"{address}: a deny policy is being deleted or changed and "
                f"its old rules could not be read — which dormant grants "
                f"wake was not decided")))
            continue
        after = change.get("after")
        if after is None:
            after = {"rules": []}  # a delete: the empty policy denies nobody
        if not isinstance(after, Mapping):
            verdicts.append(_unverified(address, (
                f"{address}: the deny policy's new rules could not be read — "
                f"which dormant grants wake was not decided")))
            continue
        old_rules, old_problems = _document_rules(before, address)
        new_rules, new_problems = _document_rules(after, address)
        if old_problems or new_problems:
            verdicts.extend(_unverified(address, (
                f"{problem} — which dormant grants wake was not decided"))
                for problem in (*old_problems, *new_problems))
            continue
        node, node_why = _attachment_node(before.get("parent"))
        if node is None:
            verdicts.append(_unverified(address, (
                f"{address}: {node_why} — which grants sit under the deny "
                f"policy was not decided")))
            continue
        reason = _require_complete(ctx.snapshot, "iam_bindings")
        verdicts.extend(_wake_findings(old_rules, new_rules, node, address,
                                       ctx.snapshot, reason))
    return verdicts


def check_deny_pair(ctx: Any) -> list:
    """C4 — the REST spelling of the woken arc: the document under review is
    the NEW deny policy, ``ctx.baseline`` the OLD one. PAIR checks bypass
    ``run_document_checks``' gate, so this one SELF-GATES: before the clean
    "wakes nothing" it consults ``require_complete(snapshot, "iam_bindings")``
    and abstains with the refusal reason; witness findings stand on the
    partial view."""
    source = getattr(ctx, "source", "") or "<policy>"
    if getattr(ctx, "baseline_kind", None) != "iam_deny_policy" \
            or not isinstance(getattr(ctx, "baseline", None), Mapping):
        return [_unverified(source, (
            f"{source}: the baseline is not an IAM deny policy — no deny "
            f"comparison was made"))]
    document = getattr(ctx, "document", None)
    if not isinstance(document, Mapping):
        return [_unverified(source, (
            f"{source}: the document under review could not be read as a "
            f"deny policy — no deny comparison was made"))]
    old_rules, old_problems = _document_rules(ctx.baseline,
                                              "the baseline deny policy")
    new_rules, new_problems = _document_rules(document,
                                              "the deny policy under review")
    if old_problems or new_problems:
        return [_unverified(source, (
            f"{source}: {problem} — which dormant grants wake was not "
            f"decided"))
            for problem in (*old_problems, *new_problems)]
    node, node_why = _policy_name_node(document)
    if node is None:
        return [_unverified(source, (
            f"{source}: {node_why} — which grants sit under the deny policy "
            f"was not decided"))]
    reason = _require_complete(ctx.snapshot, "iam_bindings")
    return _wake_findings(old_rules, new_rules, node, source, ctx.snapshot,
                          reason)


# -- the completeness two-step -------------------------------------------------


def _require_complete(snapshot: Any, category: str) -> str | None:
    """Why absence in *category* may not be read as non-existence, or None —
    through the snapshot's OWN predicate when it has one (a reconciled view
    answers from its ledger), else :func:`provenance.require_complete`, where
    a captured category on a plain snapshot reads as complete. An object
    neither can read is a view whose coverage is unknowable, which licenses
    nothing — the conservative answer, never a crash."""
    own = getattr(snapshot, "require_complete", None)
    try:
        if callable(own):
            return own(category)
        from . import provenance
        return provenance.require_complete(snapshot, category)
    except ImportError:
        logger.debug("provenance is not part of this checkout — a captured "
                     "category reads as complete")
        return None
    except Exception:  # noqa: BLE001 — an unreadable view licenses nothing
        return (f"category '{category}' coverage could not be read from this "
                f"snapshot — absence within an unreadable view cannot be "
                f"licensed")


# -- registry hooks ------------------------------------------------------------

#: Consulted by :mod:`gcp_grounding.preflight` through the lazy provider
#: :mod:`gcp_grounding.registry`.
DOCUMENT_CHECKS = (check_deny_shadow_plan, check_deny_shadow_estate,
                   check_deny_wake_plan)
PAIR_CHECKS = {"iam_deny_policy": check_deny_pair}


# Import-time soundness registration, the tf_schema_checks pattern; guarded so
# a stripped checkout still imports. ONLY C1 is registered (subset_safe on
# "roles", its one load-bearing estate read: witness findings survive a
# partial view, and a partial roles view downgrades its grounded-status
# warnings to unverified carrying the same text). C2/C3/C4 self-gate instead —
# see the module docstring's recorded deviation.
try:
    from . import provenance as _provenance
except ImportError:  # pragma: no cover — stripped checkout
    pass
else:
    _provenance.register_estate_soundness(
        "gcp_grounding.iam_deny_checks.check_deny_shadow_plan",
        "subset_safe", "roles")
