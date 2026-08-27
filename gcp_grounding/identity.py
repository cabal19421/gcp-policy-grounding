"""THE canonical estate key: one key form per category, built in ONE place.

A key that disagrees does not raise. It never matches, the miss reads as
*absent*, and absent against a view believed complete is reported as a
confident ``baseline:new`` about a resource that certainly exists. That is the
highest-consequence silent failure in a design that reconciles two sources of
current state, and it is impossible to test for after the fact — a key built
one way at map time and another way at compare time produces a report that
looks entirely reasonable.

One canonicaliser cannot disagree with itself. So there is exactly one here,
and **no other module in this tree may build an estate key**: a mapper, a
comparator, a check and a fixture all come through :func:`canonical_key` or
:func:`key_or_unresolved`.

What lives here:

- :class:`CategorySpec` and :data:`SPECS` — one spec per estate category, and
  ``tests/test_gcp_identity.py`` asserts the spec key set is EXACTLY the
  snapshot's category set, so a category added to :mod:`gcp_grounding.knowledge`
  without a key form fails there rather than silently losing drift detection.
- :func:`canonical_key` and :func:`key_or_unresolved` — TWO FACADES OVER ONE
  IMPLEMENTATION. The comparison path wants a loud failure and gets
  :class:`AmbiguousKey`; the mapper path must never fail a whole capture over
  one unbuildable key and gets a :class:`gcp_grounding.facts.Unresolved`. Two
  error conventions, never two implementations: the reason string on the
  exception IS the reason on the marker.
- :func:`normalize_self_link` — THE ONLY self-link implementation in the tree.
  ``tfsource/normalize.py`` does not get a second one; whatever it exposes
  under that name is a one-line delegation to this function. Stripping a
  self-link to a name IS the first half of a key build, and two implementations
  of the same string surgery is exactly the drift that makes a miss read as
  absence.
- :func:`alias_map` — the project-NUMBER → project-id map, read from the
  ``resource_hierarchy`` table. Where an alias is UNKNOWN the two spellings are
  kept DISTINCT rather than merged on a guess: merging two projects onto one
  row invents a comparison nobody can audit.

The facades raise for a CALLER error — an unknown category, an unknown part
name — including :func:`key_or_unresolved`. "Never raises" is a promise about
ignorance in the artifact, not a promise to swallow a bug in a mapper: a typo'd
part name silently absorbed into an ``unverified`` verdict is the same silent
failure one layer up.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import partial
from typing import Any, Callable, Mapping

from . import facts
from .core.log import get_logger

logger = get_logger(__name__)

__all__ = [
    "AmbiguousKey",
    "CategorySpec",
    "SPECS",
    "canonical_key",
    "key_or_unresolved",
    "normalize_self_link",
    "alias_map",
    "CRM_HOST",
    "HIERARCHY_KINDS",
]

#: The service that owns hierarchy-node IAM policies. A bare ``projects/<id>``
#: node is PROMOTED to ``//cloudresourcemanager.googleapis.com/projects/<id>``
#: so the terraform spelling and the snapshot spelling converge on the one the
#: table stores.
CRM_HOST = "cloudresourcemanager.googleapis.com"

#: The three hierarchy node kinds, in the ``<kind>/<id>`` spelling the
#: ``resource_hierarchy`` table stores.
HIERARCHY_KINDS = ("organizations", "folders", "projects")

# Segments a self-link's relative form may start with. Everything a GCP API
# host puts in front of one (``compute/v1``, ``v1``, ``v1beta1``) is prologue.
_SELF_LINK_ANCHORS = frozenset({"projects", "organizations", "folders",
                                "accessPolicies", "billingAccounts"})


class AmbiguousKey(ValueError):
    """The parts handed in do not determine exactly ONE estate key.

    Raised by :func:`canonical_key`, the comparison facade. Carries the
    :data:`gcp_grounding.facts.UNRESOLVED_REASONS` spelling that
    :func:`key_or_unresolved` turns into a marker, which is what keeps the two
    facades from drifting: one implementation decides, and the reason it
    decided on travels to both callers.

    ``detail`` is SHAPE-only by construction — it names parts and categories,
    never a raw attribute value (values go through
    :func:`gcp_grounding.facts.safe_repr`), so an exception message is safe in
    a traceback or a log line.
    """

    def __init__(self, category: str, reason: str, detail: str = "",
                 marker: facts.Unresolved | None = None) -> None:
        if reason not in facts.UNRESOLVED_REASONS:
            raise ValueError(f"AmbiguousKey reason {reason!r} is not one of "
                             f"{sorted(facts.UNRESOLVED_REASONS)}")
        self.category = category
        self.reason = reason
        self.detail = facts.truncate(detail)
        #: The marker a part ARRIVED as, when the key could not be built
        #: because an input was already unresolved. Preserved rather than
        #: re-minted so the marker keeps the path where it was first minted.
        self.marker = marker
        super().__init__(f"identity.{category}: {self.detail or reason} [{reason}]")


# -- the one self-link implementation -----------------------------------------


def normalize_self_link(value: str) -> str:
    """Strip a GCP self-link down to its RELATIVE resource form.

    Handles both ``googleapis.com`` spellings —
    ``https://www.googleapis.com/compute/v1/projects/p/global/networks/n`` and
    ``https://compute.googleapis.com/compute/v1/projects/p/global/networks/n``
    — plus the ``//host/…`` full-resource-name spelling, and passes the
    relative form and a bare name through unchanged. Idempotent: the output is
    always a legal input.

    **This is the only self-link implementation in this tree.** A second one is
    a second place for the same string surgery to be wrong, and a value
    normalised one way at map time and another at compare time never matches —
    and the miss reads as absent.
    """
    if not isinstance(value, str):
        raise ValueError(f"normalize_self_link expects a string, got "
                         f"{type(value).__name__}; resolve the value first")
    text = value.strip()
    lowered = text.lower()
    authority = False
    for scheme in ("https://", "http://"):
        if lowered.startswith(scheme):
            text = text[len(scheme):]
            authority = True
            break
    else:
        if text.startswith("//"):          # "//cloudresourcemanager.googleapis.com/…"
            text = text[2:]
            authority = True
    text = text.strip("/")
    if not text or not authority:
        # A relative form or a bare name is already the answer; a bare name has
        # no host to strip and must NOT be truncated looking for one.
        return text
    segments = text.split("/")[1:]         # drop the host
    for index, segment in enumerate(segments):
        if segment in _SELF_LINK_ANCHORS:
            return "/".join(segments[index:])
    return "/".join(segments)


# -- the project-number alias map ---------------------------------------------


def alias_map(snapshot: Any) -> dict[str, str]:
    """Project NUMBER → project id, read from the ``resource_hierarchy`` table.

    VPC-SC and asset inventory reference a project by number while CRM and
    terraform use the id; the three categories that key on a hierarchy node
    resolve the number through this map so both spellings land on one row.

    Returns an EMPTY map when the table was never captured (or the object has
    no such attribute at all) rather than raising: an absent alias map means
    "resolve nothing", and the builders then keep the two spellings distinct.
    Read by attribute rather than by import, so this module never imports
    :mod:`gcp_grounding.knowledge` and the estate model stays free to import
    this one.

    A number claimed by two different ids is DROPPED, not arbitrated: an
    ambiguous alias that silently picks a winner keys one project's facts onto
    another project's row.
    """
    table = getattr(snapshot, "resource_hierarchy", None)
    if not isinstance(table, Mapping):      # None (uncaptured), UNKNOWN, anything else
        return {}
    out: dict[str, str] = {}
    dropped: set[str] = set()
    for name, record in table.items():
        if not isinstance(record, Mapping) or record.get("type") != "project":
            continue
        number = record.get("number")
        if isinstance(number, bool) or not isinstance(number, (str, int)):
            continue
        number = str(number).strip()
        if not number or not isinstance(name, str):
            continue
        ident = name[len("projects/"):] if name.startswith("projects/") else name
        if not ident:
            continue
        if number in out and out[number] != ident:
            dropped.add(number)
        out[number] = ident
    for number in dropped:
        logger.debug("project number %s is claimed by more than one hierarchy "
                     "node — dropping the alias rather than picking a winner", number)
        out.pop(number, None)
    return out


# -- the specs ----------------------------------------------------------------


@dataclass(frozen=True)
class CategorySpec:
    """The one key form for one estate category, and how to build it.

    ``stored_form`` is the shape ``sx-kb-estate-tables`` actually STORES —
    quoted from :class:`gcp_grounding.knowledge.GcpSnapshot`'s own field
    documentation in the per-domain comment beside each spec. ``parts`` is
    every named part the builder accepts; anything else is a caller error.
    ``refuses`` maps a part name that must NEVER become a key to the reason it
    is refused.
    """

    category: str
    stored_form: str
    parts: tuple[str, ...]
    build: Callable[..., str]
    note: str = ""
    refuses: Mapping[str, str] = field(default_factory=dict)


# -- part readers -------------------------------------------------------------


def _text(category: str, parts: Mapping[str, Any], name: str, *,
          required: bool = True) -> str:
    """One part as a stripped string. ``None`` and ``""`` both mean NOT SUPPLIED
    — a mapper writes ``project=values.get("project")`` and must get an honest
    missing-part answer, not a crash."""
    value = parts.get(name)
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"identity.{category}: part {name!r} must be a string or "
                         f"None, got {type(value).__name__}")
    value = value.strip()
    if not value and required:
        raise AmbiguousKey(category, "ambiguous_key",
                           f"part {name!r} is empty; a key cannot be built from nothing")
    return value


def _project(category: str, parts: Mapping[str, Any], name: str = "project") -> str:
    """A project part as a bare project id. Accepts ``projects/<id>`` and a
    self-link so the caller never has to pre-strip one."""
    raw = _text(category, parts, name, required=False)
    if not raw:
        return ""
    value = normalize_self_link(raw)
    if value.startswith("projects/"):
        value = value[len("projects/"):]
    if "/" in value or not value:
        raise AmbiguousKey(category, "ambiguous_key",
                           f"part {name!r} is not a project id ({facts.safe_repr(raw)})")
    return value


def _plain(category: str, parts: Mapping[str, Any], aliases: Mapping[str, str]) -> str:
    """Categories whose stored key IS the name, with no qualification to add."""
    return _text(category, parts, "name")


# -- key builders -------------------------------------------------------------
#
# Every builder takes (category, parts, aliases) and returns the ONE stored
# spelling, or raises AmbiguousKey rather than guessing a missing qualifier.


def _build_global_collection(category: str, parts: Mapping[str, Any],
                             aliases: Mapping[str, str], *, collection: str) -> str:
    """``projects/<project>/global/<collection>/<name>`` — a self-link, the
    relative form, or a bare name plus an explicit project."""
    value = normalize_self_link(_text(category, parts, "name"))
    project = _project(category, parts)
    segments = value.split("/")
    if len(segments) == 1:
        if not project:
            raise AmbiguousKey(
                category, "missing_project",
                f"a bare {category} name needs an explicit project; guessing one "
                f"would key a resource that exists to a project it is not in")
        return f"projects/{project}/global/{collection}/{value}"
    if (len(segments) == 5 and segments[0] == "projects" and segments[2] == "global"
            and segments[3] == collection and segments[1] and segments[4]):
        if project and project != segments[1]:
            raise AmbiguousKey(category, "ambiguous_key",
                               "the name's project and the project part disagree")
        return value
    raise AmbiguousKey(category, "ambiguous_key",
                       f"{facts.safe_repr(value)} is not "
                       f"projects/<project>/global/{collection}/<name>")


def _build_subnetwork(category: str, parts: Mapping[str, Any],
                      aliases: Mapping[str, str]) -> str:
    """``projects/<project>/regions/<region>/subnetworks/<name>`` — a self-link,
    the relative form, or a bare name plus an explicit project AND region."""
    value = normalize_self_link(_text(category, parts, "name"))
    project = _project(category, parts)
    region = _text(category, parts, "region", required=False)
    if region.startswith("regions/"):
        region = region[len("regions/"):]
    elif "/" in region:
        region = normalize_self_link(region).rsplit("/", 1)[-1]
    segments = value.split("/")
    if len(segments) == 1:
        if not project:
            raise AmbiguousKey(category, "missing_project",
                               "a bare subnetwork name needs an explicit project")
        if not region:
            raise AmbiguousKey(category, "ambiguous_key",
                               "a bare subnetwork name needs an explicit region; a "
                               "subnetwork name is unique per region, not per project")
        return f"projects/{project}/regions/{region}/subnetworks/{value}"
    if (len(segments) == 6 and segments[0] == "projects" and segments[2] == "regions"
            and segments[4] == "subnetworks" and all(segments[1::2])):
        if project and project != segments[1]:
            raise AmbiguousKey(category, "ambiguous_key",
                               "the name's project and the project part disagree")
        if region and region != segments[3]:
            raise AmbiguousKey(category, "ambiguous_key",
                               "the name's region and the region part disagree")
        return value
    raise AmbiguousKey(category, "ambiguous_key",
                       f"{facts.safe_repr(value)} is not "
                       f"projects/<project>/regions/<region>/subnetworks/<name>")


def _build_hierarchical_firewall_policy(category: str, parts: Mapping[str, Any],
                                        aliases: Mapping[str, str]) -> str:
    """``organizations/<id>/locations/global/firewallPolicies/<pid>``.

    ``<pid>`` is the GENERATED policy id. A terraform ``short_name`` is REFUSED
    at the part level (see ``SPECS``): it is a different string that names the
    same policy, and accepting it would key the same policy twice. A
    ``folders/`` parent is refused too — the estate table enumerates
    organization-level policies only, so a folder-level key would be an
    existence answer about a table that never held the row.
    """
    value = normalize_self_link(_text(category, parts, "name"))
    parent = _text(category, parts, "parent", required=False)
    if parent:
        parent = normalize_self_link(parent)
        kind = parent.split("/")[0]
        if kind == "folders":
            raise AmbiguousKey(
                category, "ambiguous_key",
                "a 'folders/' parent has no key here: the estate table enumerates "
                "ORGANIZATION-level firewall policies only, so a folder-level key "
                "would answer existence against a table that never held the row")
        if len(parent.split("/")) != 2 or kind != "organizations" or not parent.split("/")[1]:
            raise AmbiguousKey(category, "ambiguous_key",
                               "part 'parent' must be spelled 'organizations/<id>'")
    segments = value.split("/")
    if len(segments) == 1:
        if not parent:
            raise AmbiguousKey(category, "ambiguous_key",
                               "a bare policy id needs its organization; a policy id "
                               "is unique per organization, not globally")
        return f"{parent}/locations/global/firewallPolicies/{value}"
    if (len(segments) == 6 and segments[2] == "locations" and segments[3] == "global"
            and segments[4] == "firewallPolicies" and segments[1] and segments[5]):
        if segments[0] == "folders":
            raise AmbiguousKey(
                category, "ambiguous_key",
                "a 'folders/' parent has no key here: the estate table enumerates "
                "ORGANIZATION-level firewall policies only")
        if segments[0] != "organizations":
            raise AmbiguousKey(category, "ambiguous_key",
                               "a hierarchical policy key starts 'organizations/<id>'")
        if parent and parent != f"{segments[0]}/{segments[1]}":
            raise AmbiguousKey(category, "ambiguous_key",
                               "the name's organization and the parent part disagree")
        return value
    raise AmbiguousKey(category, "ambiguous_key",
                       f"{facts.safe_repr(value)} is not organizations/<id>/locations/"
                       f"global/firewallPolicies/<policy-id>")


def _build_access_context(category: str, parts: Mapping[str, Any],
                          aliases: Mapping[str, str], *, collection: str) -> str:
    """``accessPolicies/<n>/<collection>/<name>`` — the relative form, or a bare
    name plus an explicit access policy."""
    value = normalize_self_link(_text(category, parts, "name"))
    policy = _text(category, parts, "access_policy", required=False)
    if policy.startswith("accessPolicies/"):
        policy = policy[len("accessPolicies/"):]
    if "/" in policy:
        raise AmbiguousKey(category, "ambiguous_key",
                           "part 'access_policy' is 'accessPolicies/<n>' or '<n>'")
    segments = value.split("/")
    if len(segments) == 1:
        if not policy:
            raise AmbiguousKey(category, "ambiguous_key",
                               f"a bare {category} name needs its access policy")
        return f"accessPolicies/{policy}/{collection}/{value}"
    if (len(segments) == 4 and segments[0] == "accessPolicies"
            and segments[2] == collection and segments[1] and segments[3]):
        if policy and policy != segments[1]:
            raise AmbiguousKey(category, "ambiguous_key",
                               "the name's access policy and the access_policy part disagree")
        return value
    raise AmbiguousKey(category, "ambiguous_key",
                       f"{facts.safe_repr(value)} is not "
                       f"accessPolicies/<n>/{collection}/<name>")


def _canonical_node(category: str, value: str, aliases: Mapping[str, str]) -> str:
    """``<organizations|folders|projects>/<id>``, resolving a project NUMBER
    through the alias map. An UNKNOWN number stays a number: two spellings kept
    distinct cost one extra row, while merging them on a guess attributes one
    project's policy to another."""
    segments = value.split("/")
    if len(segments) != 2 or segments[0] not in HIERARCHY_KINDS or not segments[1]:
        raise AmbiguousKey(category, "ambiguous_key",
                           f"{facts.safe_repr(value)} is not "
                           f"'<organizations|folders|projects>/<id>'")
    kind, ident = segments
    if kind == "projects" and ident.isdigit():
        resolved = aliases.get(ident)
        if resolved:
            return f"projects/{resolved}"
        logger.debug("project number %s is not in the alias map — keeping the number "
                     "spelling distinct rather than guessing an id", ident)
    return value


def _build_hierarchy_node(category: str, parts: Mapping[str, Any],
                          aliases: Mapping[str, str]) -> str:
    return _canonical_node(category, normalize_self_link(_text(category, parts, "name")),
                           aliases)


def _split_full_resource_name(value: str) -> tuple[str, str]:
    """``("//host/rest")`` → ``(host, rest)``; anything else → ``("", relative)``.

    Done BEFORE :func:`normalize_self_link` because that function strips the
    host, and for an IAM binding the host is part of the stored key.
    """
    text = value.strip()
    if text.startswith("//"):
        host, _, rest = text[2:].partition("/")
        return host, rest.strip("/")
    return "", normalize_self_link(text)


def _build_iam_binding(category: str, parts: Mapping[str, Any],
                       aliases: Mapping[str, str]) -> str:
    """``//<service>/<resource>`` — and a bare ``projects/<id>`` node is PROMOTED
    to the CRM full resource name, so the terraform spelling and the stored
    spelling converge instead of producing two rows for one policy."""
    host, rest = _split_full_resource_name(_text(category, parts, "name"))
    segments = rest.split("/")
    if len(segments) == 2 and segments[0] in HIERARCHY_KINDS and segments[1]:
        return f"//{host or CRM_HOST}/{_canonical_node(category, rest, aliases)}"
    if host and rest:
        return f"//{host}/{rest}"
    raise AmbiguousKey(
        category, "ambiguous_key",
        "an IAM binding key is a full resource name ('//<service>/<resource>'); only "
        "a hierarchy node (projects/<id>, folders/<id>, organizations/<id>) can be "
        "promoted to one, because only its service is known without guessing")


def _build_iam_deny_policy(category: str, parts: Mapping[str, Any],
                           aliases: Mapping[str, str]) -> str:
    """``policies/<url-encoded-attachment>/denypolicies/<id>`` — the v2 REST
    resource name, taken as stored: the attachment segment stays ENCODED
    because that is the API's own spelling of the key, and a name outside the
    shape is refused rather than reshaped — a guessed attachment would let the
    containment walk govern the wrong node."""
    name = _text(category, parts, "name").strip().strip("/")
    segments = name.split("/")
    if (len(segments) == 4 and segments[0] == "policies"
            and segments[2] == "denypolicies" and segments[1] and segments[3]):
        return name
    raise AmbiguousKey(
        category, "ambiguous_key",
        "an IAM deny policy key is the v2 resource name "
        "('policies/<url-encoded-attachment>/denypolicies/<id>'); anything "
        "else cannot be promoted to one without guessing the attachment")


def _canonical_constraint(category: str, value: str) -> str:
    """The parentless ``constraints/<name>`` form. The API answers
    parent-qualified names (``organizations/123/constraints/x``) while
    snapshots and policy files use the short one; ``fetch._short_constraint_name``
    applies the same reduction at CAPTURE time, before a name ever reaches this
    module."""
    text = value.strip()
    if "/constraints/" in text:
        return "constraints/" + text.rsplit("/constraints/", 1)[1]
    if text.startswith("constraints/"):
        return text
    return f"constraints/{text}"


def _build_constraint(category: str, parts: Mapping[str, Any],
                      aliases: Mapping[str, str]) -> str:
    return _canonical_constraint(category, _text(category, parts, "name"))


def _build_org_policy(category: str, parts: Mapping[str, Any],
                      aliases: Mapping[str, str]) -> str:
    """The composite ``<node>|<constraint>``, each half canonicalised
    INDEPENDENTLY by the half's own category. Nobody else hand-joins this
    string: a hand-join with an un-canonicalised half is a key that misses."""
    name = _text(category, parts, "name", required=False)
    node = _text(category, parts, "node", required=False)
    constraint = _text(category, parts, "constraint", required=False)
    if name:
        if node or constraint:
            raise AmbiguousKey(category, "ambiguous_key",
                               "pass the composite key OR its two halves, never both")
        halves = name.split("|")
        if len(halves) != 2 or not halves[0].strip() or not halves[1].strip():
            raise AmbiguousKey(category, "ambiguous_key",
                               "the composite key is exactly '<node>|<constraint>' "
                               "with a single '|' separator")
        node, constraint = halves[0].strip(), halves[1].strip()
    if not node or not constraint:
        raise AmbiguousKey(category, "ambiguous_key",
                           "an org-policy key needs BOTH a node and a constraint")
    if "|" in node or "|" in constraint:
        raise AmbiguousKey(category, "ambiguous_key",
                           "neither half of an org-policy key may contain '|'")
    canonical_node = _canonical_node(category, normalize_self_link(node), aliases)
    return f"{canonical_node}|{_canonical_constraint(category, constraint)}"


def _build_service_account(category: str, parts: Mapping[str, Any],
                           aliases: Mapping[str, str]) -> str:
    """The bare email. The ``serviceAccount:`` prefix is STRIPPED — this
    category is defined without it, unlike ``principals``, where the prefix is
    part of the identity — and the email is NEVER case-folded, because a GCP
    email local part is case-sensitive in practice."""
    value = _text(category, parts, "name")
    if value.startswith("serviceAccount:"):
        value = value[len("serviceAccount:"):].strip()
    if "/serviceAccounts/" in value:        # projects/<p>/serviceAccounts/<email>
        value = value.rsplit("/serviceAccounts/", 1)[1].strip()
    if not value:
        raise AmbiguousKey(category, "ambiguous_key",
                           "nothing is left of the service account after stripping "
                           "its prefix")
    return value


def _build_role(category: str, parts: Mapping[str, Any],
                aliases: Mapping[str, str]) -> str:
    """``roles/<id>`` for a predefined role, ``projects/<p>/roles/<id>`` or
    ``organizations/<o>/roles/<id>`` for a custom one. A bare role id is
    REFUSED: it is either a predefined role or a custom role in some project,
    and the two are different rows."""
    value = normalize_self_link(_text(category, parts, "name"))
    project = _project(category, parts)
    organization = _text(category, parts, "organization", required=False)
    if organization.startswith("organizations/"):
        organization = organization[len("organizations/"):]
    segments = value.split("/")
    if len(segments) == 1:
        if project and organization:
            raise AmbiguousKey(category, "ambiguous_key",
                               "a custom role lives in a project OR an organization, "
                               "never both")
        if project:
            return f"projects/{project}/roles/{value}"
        if organization:
            return f"organizations/{organization}/roles/{value}"
        raise AmbiguousKey(category, "ambiguous_key",
                           "a bare role id is either a predefined role or a custom "
                           "role in some project; pass project= or organization=")
    if len(segments) == 2 and segments[0] == "roles" and segments[1]:
        return value
    if (len(segments) == 4 and segments[0] in ("projects", "organizations")
            and segments[2] == "roles" and segments[1] and segments[3]):
        return value
    raise AmbiguousKey(category, "ambiguous_key",
                       f"{facts.safe_repr(value)} is not a role name")


# -- one spec per estate category ---------------------------------------------
#
# EXACTLY the categories GcpSnapshot carries. The acceptance test asserts that
# equality, so a category added to the snapshot without a key form fails there
# rather than silently losing drift detection.

SPECS: Mapping[str, CategorySpec] = {
    # roles — knowledge.GcpSnapshot.roles: "role name -> record". The committed
    # fixture stores both spellings: "roles/bigquery.dataViewer" (predefined)
    # and "projects/acme-prod/roles/ciDeployer" (custom).
    "roles": CategorySpec(
        "roles", "roles/<id> | projects/<p>/roles/<id> | organizations/<o>/roles/<id>",
        ("name", "project", "organization"), _build_role,
        note="terraform's role_id needs its project; a bare id is refused"),

    # permissions — "flat enumeration of permission names": the dotted name is
    # already the vocabulary's own spelling ("iam.roles.create").
    "permissions": CategorySpec(
        "permissions", "<service>.<resource>.<verb>", ("name",), _plain,
        note="Google's vocabulary; there is nothing to qualify"),

    # principals — "principal identifiers ('user:…', 'serviceAccount:…',
    # 'group:…', …)". The type prefix IS part of the identity here; contrast
    # service_accounts, which is defined WITHOUT it.
    "principals": CategorySpec(
        "principals", "<type>:<identity>", ("name",), _plain,
        note="the prefix is kept: 'user:a@x' and 'serviceAccount:a@x' are not one"),

    # constraints — "org-policy constraint name -> record", stored parentless as
    # "constraints/<name>" (fetch._short_constraint_name reduces the API's
    # parent-qualified spelling at capture time).
    "constraints": CategorySpec(
        "constraints", "constraints/<name>", ("name",), _build_constraint,
        note="also the second half of every org_policies key"),

    # resource_types — "asset types (e.g. 'compute.googleapis.com/Instance')".
    # The fixture also stores terraform type names; both are already canonical.
    "resource_types": CategorySpec(
        "resource_types", "<service>/<Type> | <terraform_type>", ("name",), _plain,
        note="the provider's own vocabulary; nothing to qualify"),

    # networks — GcpSnapshot.networks: "VPC networks as
    # 'projects/<project>/global/networks/<name>' (extractors normalize
    # self-links by stripping the 'https://www.googleapis.com/compute/v1/'
    # prefix)".
    "networks": CategorySpec(
        "networks", "projects/<project>/global/networks/<name>",
        ("name", "project"), partial(_build_global_collection, collection="networks"),
        note="a self-link, the relative form, or a bare name plus a project"),

    # subnetworks — "subnetworks as
    # 'projects/<project>/regions/<region>/subnetworks/<name>'".
    "subnetworks": CategorySpec(
        "subnetworks", "projects/<project>/regions/<region>/subnetworks/<name>",
        ("name", "project", "region"), _build_subnetwork,
        note="a bare name needs BOTH project and region: names are per-region"),

    # network_tags — "bare network tag strings (e.g. 'web', 'bastion')".
    "network_tags": CategorySpec(
        "network_tags", "<tag>", ("name",), _plain,
        note="never case-folded: the tag a rule names is the tag it names"),

    # service_accounts — "bare service-account emails … deliberately WITHOUT the
    # 'serviceAccount:' prefix, so this category is distinct from principals".
    "service_accounts": CategorySpec(
        "service_accounts", "<account>@<project>.iam.gserviceaccount.com",
        ("name",), _build_service_account,
        note="prefix stripped, case preserved (an email local part is case-sensitive)"),

    # access_levels — "access levels as
    # 'accessPolicies/<n>/accessLevels/<name>'".
    "access_levels": CategorySpec(
        "access_levels", "accessPolicies/<n>/accessLevels/<name>",
        ("name", "access_policy"),
        partial(_build_access_context, collection="accessLevels"),
        note="a bare name needs its access policy"),

    # restricted_services — "VPC-SC restricted service hostnames (e.g.
    # 'storage.googleapis.com')".
    "restricted_services": CategorySpec(
        "restricted_services", "<service>.googleapis.com", ("name",), _plain,
        note="the service hostname is already the identity"),

    # firewall_rules — "VPC firewall rules keyed
    # 'projects/<p>/global/firewalls/<name>'". The terraform ADDRESS is
    # deliberately NOT the identity: renaming google_compute_firewall.a to .b
    # must not read as a delete plus a create of the same rule.
    "firewall_rules": CategorySpec(
        "firewall_rules", "projects/<project>/global/firewalls/<name>",
        ("name", "project"), partial(_build_global_collection, collection="firewalls"),
        note="the terraform address is NOT the identity; the rule name is"),

    # hierarchical_firewall_policies — "keyed
    # 'organizations/<id>/locations/global/firewallPolicies/<pid>'".
    "hierarchical_firewall_policies": CategorySpec(
        "hierarchical_firewall_policies",
        "organizations/<id>/locations/global/firewallPolicies/<policy-id>",
        ("name", "parent"), _build_hierarchical_firewall_policy,
        note="the GENERATED policy id; a folders/ parent has no row in this table",
        refuses={
            "short_name": "terraform's 'short_name' is not the policy id: the estate "
                          "table keys the GENERATED numeric id, and accepting both "
                          "spellings would key one policy to two rows — resolve the "
                          "id from the artifact, or leave the fact unresolved",
        }),

    # cloud_armor_policies — "Cloud Armor security policies keyed
    # 'projects/<p>/global/securityPolicies/<name>'". Same project-qualification
    # and missing-project rules as firewall_rules, and for the same reason.
    "cloud_armor_policies": CategorySpec(
        "cloud_armor_policies", "projects/<project>/global/securityPolicies/<name>",
        ("name", "project"),
        partial(_build_global_collection, collection="securityPolicies"),
        note="a self-link, the relative form, or a bare name plus a project"),

    # vpc_sc_perimeters — "VPC-SC service perimeters keyed
    # 'accessPolicies/<n>/servicePerimeters/<name>'".
    "vpc_sc_perimeters": CategorySpec(
        "vpc_sc_perimeters", "accessPolicies/<n>/servicePerimeters/<name>",
        ("name", "access_policy"),
        partial(_build_access_context, collection="servicePerimeters"),
        note="a bare name needs its access policy"),

    # resource_hierarchy — "nodes keyed by node name ('organizations/1',
    # 'folders/2', 'projects/acme-prod')", with the projects/<number> alias
    # resolved through alias_map when it is known.
    "resource_hierarchy": CategorySpec(
        "resource_hierarchy", "<organizations|folders|projects>/<id>",
        ("name",), _build_hierarchy_node,
        note="a project NUMBER resolves through the alias map, or stays distinct"),

    # iam_bindings — "IAM binding sets keyed by resource full name
    # ('//cloudresourcemanager.googleapis.com/projects/acme-prod')".
    "iam_bindings": CategorySpec(
        "iam_bindings", "//<service>/<resource>",
        ("name",), _build_iam_binding,
        note="a bare projects/<id> node is PROMOTED to the CRM full resource name"),

    # org_policies — "EFFECTIVE org-policy set-policies keyed
    # '<node>|<constraint>'", each half canonicalised by its own category.
    "org_policies": CategorySpec(
        "org_policies", "<node>|<constraint>",
        ("name", "node", "constraint"), _build_org_policy,
        note="the only place this composite is joined"),

    # iam_deny_policies — "IAM v2 deny policies keyed by the v2 REST resource
    # name ('policies/<url-encoded-attachment>/denypolicies/<id>')" — the
    # API's own one spelling; the knowledge parser cross-checks the encoded
    # attachment segment against the record's decoded attachment_point.
    "iam_deny_policies": CategorySpec(
        "iam_deny_policies", "policies/<url-encoded-attachment>/denypolicies/<id>",
        ("name",), _build_iam_deny_policy,
        note="a name outside the v2 denypolicies shape is refused, never guessed"),
}


# -- the two facades over the one implementation ------------------------------


def _build(category: str, parts: Mapping[str, Any],
           aliases: Mapping[str, str] | None) -> str:
    spec = SPECS.get(category)
    if spec is None:
        raise ValueError(f"identity: {category!r} is not an estate category; "
                         f"expected one of {sorted(SPECS)}")
    for part_name in sorted(parts):
        refused = spec.refuses.get(part_name)
        if refused is not None:
            raise AmbiguousKey(category, "ambiguous_key", refused)
        if part_name not in spec.parts:
            raise ValueError(f"identity.{category}: unknown key part {part_name!r}; "
                             f"this category accepts {list(spec.parts)} — a part name "
                             f"nobody reads is a qualifier silently dropped from the key")
    for part_name in sorted(parts):
        value = parts[part_name]
        if facts.is_unresolved(value):
            # The key cannot be built because an INPUT was never resolved. Carry
            # the original marker so it keeps the path where it was minted.
            raise AmbiguousKey(category, value.reason,
                               f"part {part_name!r} is unresolved", marker=value)
    return spec.build(category, parts, aliases or {})


def canonical_key(category: str, *, aliases: Mapping[str, str] | None = None,
                  **parts: Any) -> str:
    """THE key for ``category``, or :class:`AmbiguousKey` — the COMPARISON path.

    A comparison that cannot name the thing it is comparing must stop: a key
    quietly built from an assumed project is a confident answer about a
    resource somewhere else. ``aliases`` is :func:`alias_map`'s output and is
    read by the three categories that key on a hierarchy node.
    """
    return _build(category, parts, aliases)


def key_or_unresolved(category: str, *, aliases: Mapping[str, str] | None = None,
                      path: str = "", **parts: Any
                      ) -> str | facts.Unresolved:
    """THE key for ``category``, or a :class:`gcp_grounding.facts.Unresolved` —
    the MAPPER path, which must never fail a whole capture over one key.

    Same implementation and same reasons as :func:`canonical_key`; only the
    error convention differs. ``path`` names where the value came from for the
    marker; it defaults to the category, which is always attributable.

    Still raises for a CALLER error (unknown category, unknown part name):
    those are bugs in the mapper, not ignorance about the artifact, and burying
    one in a marker hides it inside an honest-looking abstention.
    """
    try:
        return _build(category, parts, aliases)
    except AmbiguousKey as exc:
        if exc.marker is not None:
            return exc.marker
        # A "sensitive" marker must carry no detail — facts.Unresolved refuses
        # one, because the detail is exactly the value it exists to withhold.
        detail = "" if exc.reason == "sensitive" else exc.detail
        return facts.Unresolved(exc.reason, path or f"identity.{category}", detail)
