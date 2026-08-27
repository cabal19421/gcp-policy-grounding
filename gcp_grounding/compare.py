"""THE one record comparator: do two rows SAY the same thing?

:mod:`gcp_grounding.identity` answers the first question a reconciliation asks
— *are these two rows the same resource*. This module answers the second —
*do they say the same thing* — and it is a separate FILE on purpose. The seam
between the two questions is real (a key form is about names, a comparison is
about content), and eighteen category specs plus every key form plus the whole
comparison algebra in one diff is large enough that a reviewer, human or
otherwise, silently stops reading.

What lives here:

- :func:`comparable` — one record's deterministic, hashable, ORDER-NORMALISED
  form, built on :func:`gcp_grounding.claims.freeze`. Two views of one
  unchanged resource must produce the SAME form: a set-valued field written in
  a different order, a protocol spelled ``TCP`` in terraform and ``tcp`` by the
  API, a port written ``22`` against one written ``22-22`` are the same fact,
  and a comparator that reports them as changes is a comparator nobody reads
  twice.
- :func:`compare` — the union-of-keys walk that yields :class:`FieldDiff`, each
  carrying the SEVERITY the field's classification earned.

**Refuse on surprise.** A key that no list classifies yields an
``unmergeable`` diff NAMING the field. It is never silently equal and never
guessed material: a provider that grows a field must make a human look at it
once. That rule is normative and it is the reason the per-category lists below
are exhaustive rather than illustrative.

**The two pinned lists, and why they are two.** :data:`VOLATILE_IGNORED` is
server-assigned or bookkeeping content — etags, self-links, fingerprints,
timestamps, the terraform address — that differs between two views of the SAME
resource for reasons that are not about the estate. It is IGNORED, and ignored
means *no diff at all*: classifying it merely as benign would not ignore it,
because ``drift.drift_verdicts`` turns every benign diff into a ``drift``
verdict and a terraform view against an API view of one unchanged firewall
would then emit a wall of drift about etags. :data:`BENIGN_REPORTED` is the
much smaller set that is genuinely worth SAYING and genuinely not
security-relevant. Both lists are RECOGNISED names, so refuse-on-surprise is
untouched: a volatile field is classified and silent, not unclassified and
loud.

The IAM policy ``version`` field is in NEITHER list. A policy version is
semantic — version 3 admits conditional bindings that version 1 does not — so
it is a security field and a change to it is ``material``.
"""

from __future__ import annotations

from dataclasses import dataclass, field as _spec_field
from typing import Any, Iterable, Mapping

from . import claims, facts
from .core.log import get_logger

logger = get_logger(__name__)

__all__ = [
    "Incomparable",
    "FieldDiff",
    "CategoryCompare",
    "FIELDS",
    "SEVERITIES",
    "MATERIAL",
    "BENIGN",
    "UNMERGEABLE",
    "VOLATILE_IGNORED",
    "BENIGN_REPORTED",
    "BY_INDEX",
    "BY_VALUE",
    "PERIMETER_CROSS_PAIR",
    "DRY_RUN_SPEC_NOTE",
    "comparable",
    "compare",
]


#: A field whose difference changes what the estate PERMITS.
MATERIAL = "material"
#: A field whose difference is worth saying and grants nothing.
BENIGN = "benign"
#: A field this comparator refuses to merge — an unclassified key, or a pairing
#: it will not invent. Never a silent equality.
UNMERGEABLE = "unmergeable"

#: Every severity a :class:`FieldDiff` may carry. There is no fourth: a
#: comparator that can say "probably fine" is a comparator that says it.
SEVERITIES = (MATERIAL, BENIGN, UNMERGEABLE)

#: Server-assigned or bookkeeping fields, IGNORED when comparing — they yield
#: no diff at all. Two views of the same unchanged resource disagree on every
#: one of these for reasons that are not about the estate.
VOLATILE_IGNORED = frozenset({
    "etag", "self_link", "selfLink", "id", "fingerprint",
    "creation_timestamp", "creationTimestamp", "labels",
    "terraform_address", "project_number",
})

#: Fields reported as ``benign`` in EVERY category. Each category adds its own
#: in :attr:`CategoryCompare.benign_fields`; this is the shared floor.
BENIGN_REPORTED = frozenset({"description"})

#: :attr:`CategoryCompare.subrecord_keys` marker — the element's POSITION is its
#: identity, for a collection whose order is semantic (``org_policies`` rules).
BY_INDEX = "<index>"
#: :attr:`CategoryCompare.subrecord_keys` marker — the whole element is its own
#: identity, for a collection that has been normalised into atoms (the
#: expanded ``iam_bindings`` triples).
BY_VALUE = "<value>"

#: The reason a ``spec``-only view is refused against a ``status``-only view.
#: The naming is genuinely counterintuitive and the comment is load-bearing: in
#: VPC-SC a ``status`` block is the ENFORCED configuration and a ``spec`` block
#: is the DRY-RUN one.
PERIMETER_CROSS_PAIR = (
    "one view carries only the perimeter's dry-run block and the other only its "
    "enforced block (in VPC-SC 'status' is ENFORCED and 'spec' is DRY-RUN); they "
    "are never cross-paired, because pairing them would let a dry-run perimeter "
    "read as enforced"
)

#: Why an org policy's ``dry_run_spec`` is reported rather than dropped.
DRY_RUN_SPEC_NOTE = (
    "'dry_run_spec' is the org policy's DRY-RUN half: it is evaluated and logged, "
    "never enforced, so a difference here grants nothing — and it is reported "
    "rather than dropped so its presence stays visible"
)

_BOOL_FIELDS = frozenset({"disabled", "preview"})
_PORT_MIN, _PORT_MAX = 0, 65535
# A layer4 entry's canonical form can carry a protocol and its ports and
# nothing else, so any other key would be silently dropped by the very act of
# normalising. Refuse instead.
_LAYER4_KEYS = frozenset({"protocol", "ports"})
# The keys one IAM binding may carry. Expansion rewrites 'members' into one
# 'member' per triple; see _expanded.
_BINDING_KEYS = frozenset({"role", "members", "condition"})


class Incomparable(ValueError):
    """The two records cannot be compared AT ALL, so no diff is emitted.

    Raised — never returned as a diff — when normalisation itself cannot
    proceed: an unparseable port string, a layer4 entry carrying content the
    canonical form cannot hold, an IAM binding with an unrecognised key. The
    last of those is deliberately whole-record rather than per-field, because a
    partially compared IAM policy is a policy whose difference you did not see.

    ``detail`` is SHAPE-only: it names fields and categories and renders values
    through :func:`gcp_grounding.facts.safe_repr`, so the message is safe in a
    traceback or a log line.
    """

    def __init__(self, category: str, detail: str) -> None:
        self.category = category
        self.detail = facts.truncate(detail)
        super().__init__(f"compare.{category}: {self.detail}")


@dataclass(frozen=True)
class FieldDiff:
    """One field on which two views of one resource disagree.

    ``field`` is the field's path WITHIN the record, dotted and bracket-free:
    ``source_ranges`` at the top level, ``bindings.members`` for a field inside
    a subrecord. ``subkey`` is the element's position within the collection
    named by the first segment, and is empty for a top-level field.
    :attr:`path` renders the two together as ``bindings[0].members``, so a
    drift or explain message can name a POSITION rather than gesture at a list.

    ``left`` and ``right`` are the NORMALISED values (:func:`comparable`'s
    forms), and a side that does not carry the field at all is rendered as
    ``None``.
    """

    field: str
    subkey: str
    severity: str
    left: Any
    right: Any
    note: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"FieldDiff severity {self.severity!r} is not one of "
                             f"{list(SEVERITIES)}")

    @property
    def path(self) -> str:
        """``source_ranges`` | ``bindings[0]`` | ``bindings[0].members``."""
        if not self.subkey:
            return self.field
        head, _, rest = self.field.partition(".")
        rendered = f"{head}[{self.subkey}]"
        return f"{rendered}.{rest}" if rest else rendered


@dataclass(frozen=True)
class CategoryCompare:
    """One category's field classification and its order semantics.

    ``security_fields`` and ``benign_fields`` classify a field name at ANY
    depth — a name means the same thing inside a subrecord as it does at the
    top of a record, and one table per category is one place to be wrong rather
    than one per nesting level. Same for ``set_fields`` and ``ordered_fields``:
    ``src_ip_ranges`` is a set whether it sits on a rule or inside its
    ``match``.

    ``benign_fields`` maps a field to the NOTE the diff carries, which is how
    ``org_policies.dry_run_spec`` stays visible without reading as enforcement.
    ``subrecord_keys`` maps a collection field to the key its elements are aligned
    by — a field name, :data:`BY_INDEX`, or :data:`BY_VALUE`.
    """

    category: str
    security_fields: frozenset[str] = frozenset()
    benign_fields: Mapping[str, str] = _spec_field(default_factory=dict)
    set_fields: frozenset[str] = frozenset()
    ordered_fields: frozenset[str] = frozenset()
    subrecord_keys: Mapping[str, str] = _spec_field(default_factory=dict)
    note: str = ""


# -- one field table per estate category --------------------------------------
#
# EXACTLY the categories GcpSnapshot carries, and exactly the categories
# identity.SPECS keys — the acceptance test asserts that equality, so a
# category added to the estate model without a field table fails there rather
# than silently reporting every one of its fields as unmergeable.
#
# A category's stored record shape is quoted from knowledge.GcpSnapshot's own
# field documentation beside each entry. The nine flat vocabularies have no
# record at all: their name IS their content, so they carry no field lists.

_FLAT_NOTE = "a flat vocabulary: the name IS the record, so there is no field to compare"

FIELDS: Mapping[str, CategoryCompare] = {
    # roles — "role name -> record ({'title', 'stage', 'included_permissions', …})".
    # included_permissions is what a role GRANTS, and the permission order in
    # the array carries nothing.
    "roles": CategoryCompare(
        "roles",
        security_fields=frozenset({"included_permissions"}),
        benign_fields={"title": "", "stage": ""},
        set_fields=frozenset({"included_permissions"})),

    # permissions — "flat enumeration of permission names".
    "permissions": CategoryCompare("permissions", note=_FLAT_NOTE),

    # principals — "principal identifiers ('user:…', 'serviceAccount:…', …)".
    "principals": CategoryCompare("principals", note=_FLAT_NOTE),

    # constraints — "constraint name -> record ({'value_type': 'boolean'|'list'})".
    # value_type is semantic: the same policy body means different things
    # against a boolean constraint and a list one.
    "constraints": CategoryCompare(
        "constraints",
        security_fields=frozenset({"value_type"})),

    # resource_types — "asset types (e.g. 'compute.googleapis.com/Instance')".
    "resource_types": CategoryCompare("resource_types", note=_FLAT_NOTE),

    # networks / subnetworks / network_tags / service_accounts / access_levels /
    # restricted_services — flat name sets, all of them.
    "networks": CategoryCompare("networks", note=_FLAT_NOTE),
    "subnetworks": CategoryCompare("subnetworks", note=_FLAT_NOTE),
    "network_tags": CategoryCompare("network_tags", note=_FLAT_NOTE),
    "service_accounts": CategoryCompare("service_accounts", note=_FLAT_NOTE),
    "access_levels": CategoryCompare("access_levels", note=_FLAT_NOTE),
    "restricted_services": CategoryCompare("restricted_services", note=_FLAT_NOTE),

    # firewall_rules — "network/direction/action/priority/disabled and the tag,
    # range, service-account and layer4 match sets". EVERY field of a firewall
    # rule decides what the rule permits, so every one of them is material; the
    # match sets are sets, and their order carries nothing.
    "firewall_rules": CategoryCompare(
        "firewall_rules",
        security_fields=frozenset({
            "action", "direction", "disabled", "network", "priority", "layer4",
            "source_ranges", "destination_ranges", "source_tags", "target_tags",
            "source_service_accounts", "target_service_accounts"}),
        set_fields=frozenset({
            "source_ranges", "destination_ranges", "source_tags", "target_tags",
            "source_service_accounts", "target_service_accounts"})),

    # hierarchical_firewall_policies — "hierarchy attachments and
    # priority-ordered rules". A rule's identity is its PRIORITY (the slot it
    # occupies), not its position in the array, so the rules collection is a
    # SET and its elements align by priority.
    "hierarchical_firewall_policies": CategoryCompare(
        "hierarchical_firewall_policies",
        security_fields=frozenset({
            "attachments", "rules",
            "action", "direction", "disabled", "match", "priority",
            "target_resources", "target_secure_tags", "target_service_accounts",
            "src_ip_ranges", "dest_ip_ranges", "layer4"}),
        set_fields=frozenset({
            "attachments", "rules", "target_resources", "target_secure_tags",
            "target_service_accounts", "src_ip_ranges", "dest_ip_ranges"}),
        subrecord_keys={"rules": "priority"}),

    # cloud_armor_policies — "record: type + rules". Same slot identity as the
    # hierarchical policies: an Armor rule is keyed by its priority.
    "cloud_armor_policies": CategoryCompare(
        "cloud_armor_policies",
        security_fields=frozenset({
            "type", "rules", "action", "match", "preview", "priority",
            "expr", "versioned_expr", "src_ip_ranges"}),
        set_fields=frozenset({"rules", "src_ip_ranges"}),
        subrecord_keys={"rules": "priority"}),

    # vpc_sc_perimeters — "perimeter_type, use_explicit_dry_run_spec, and the
    # status/spec config blocks". THE PERIMETER RULE lives in _perimeter_diff:
    # status is ENFORCED, spec is DRY-RUN, and they are compared
    # status-to-status and spec-to-spec only.
    "vpc_sc_perimeters": CategoryCompare(
        "vpc_sc_perimeters",
        security_fields=frozenset({
            "perimeter_type", "use_explicit_dry_run_spec", "status", "spec",
            "access_levels", "resources", "restricted_services",
            "egress_policies", "ingress_policies",
            "egress_from", "egress_to", "ingress_from", "ingress_to",
            "identities", "identity_type", "sources", "source_restriction",
            "operations", "service_name", "method_selectors", "method",
            "permission", "vpc_accessible_services"}),
        benign_fields={"title": ""},
        set_fields=frozenset({
            "access_levels", "resources", "restricted_services",
            "egress_policies", "ingress_policies", "identities", "sources",
            "operations", "method_selectors"})),

    # resource_hierarchy — "record: parent/type/number/display_name". The shape
    # of the tree decides what a policy inherits; the number and the display
    # name are labels for the same node.
    "resource_hierarchy": CategoryCompare(
        "resource_hierarchy",
        security_fields=frozenset({"parent", "type"}),
        benign_fields={"display_name": "", "number": ""}),

    # iam_bindings — "IAM binding sets keyed by resource full name". 'version'
    # is a SECURITY field: version 3 admits conditional bindings that version 1
    # does not. The bindings collection is expanded into role-member-condition
    # triples (see _expanded), so two sources' different GROUPING of the same
    # members cannot register as a difference.
    "iam_bindings": CategoryCompare(
        "iam_bindings",
        security_fields=frozenset({
            "bindings", "version", "role", "member", "members", "condition"}),
        set_fields=frozenset({"bindings", "members"}),
        subrecord_keys={"bindings": BY_VALUE}),

    # org_policies — "EFFECTIVE org-policy set-policies keyed
    # '<node>|<constraint>'". The rules array is ORDERED — an org policy rule
    # has no priority, so its POSITION is its precedence — which is why it is
    # the one rules collection here that aligns by index. dry_run_spec is
    # benign WITH A NOTE.
    "org_policies": CategoryCompare(
        "org_policies",
        security_fields=frozenset({
            "constraint", "node", "inherit_from_parent", "reset", "rules",
            "allow_all", "deny_all", "allowed_values", "denied_values",
            "condition", "enforce"}),
        benign_fields={"dry_run_spec": DRY_RUN_SPEC_NOTE},
        set_fields=frozenset({"allowed_values", "denied_values"}),
        ordered_fields=frozenset({"rules"}),
        subrecord_keys={"rules": BY_INDEX}),

    # iam_deny_policies — "attachment_point (decoded node) + rules". EVERY
    # field of a deny rule decides who is denied what: the four
    # principal/permission lists are SETS (GCP applies them as memberships,
    # and their order carries nothing), while the rules array itself — like an
    # org policy's — has no per-rule priority, so its POSITION is its
    # identity and it aligns by index.
    "iam_deny_policies": CategoryCompare(
        "iam_deny_policies",
        security_fields=frozenset({
            "attachment_point", "rules", "denied_principals",
            "exception_principals", "denied_permissions",
            "exception_permissions", "denial_condition", "expression"}),
        set_fields=frozenset({
            "denied_principals", "exception_principals",
            "denied_permissions", "exception_permissions"}),
        ordered_fields=frozenset({"rules"}),
        subrecord_keys={"rules": BY_INDEX}),
}


def _spec(category: str) -> CategoryCompare:
    spec = FIELDS.get(category)
    if spec is None:
        raise ValueError(f"compare: {category!r} is not an estate category; expected "
                         f"one of {sorted(FIELDS)}")
    return spec


# -- normalisation ------------------------------------------------------------


def _frozen_map(pairs: Iterable[tuple[str, Any]]) -> tuple[Any, ...]:
    """The :func:`gcp_grounding.claims.freeze` MAP form, assembled by hand.

    ``freeze`` cannot build this one itself: a normalised set field is a
    ``frozenset`` and ``freeze`` refuses to freeze one. Sorting is by KEY
    alone, because two frozensets do not order.
    """
    return ("__map__", tuple(sorted(((str(k), v) for k, v in pairs),
                                    key=lambda item: item[0])))


def _freeze(category: str, name: str, value: Any) -> Any:
    try:
        return claims.freeze(value)
    except ValueError as exc:
        where = f"field {name!r}" if name else "a nested value"
        raise Incomparable(category, f"{where} cannot be frozen ({exc}); a record that "
                                     f"smuggles an object past this point compares "
                                     f"unequal to itself") from exc


def _port_interval(category: str, value: Any) -> tuple[int, int]:
    """``"22"`` → ``(22, 22)``, ``"0-65535"`` → ``(0, 65535)``.

    A single port becomes a ONE-ELEMENT interval so the two spellings of one
    port converge. Anything else raises :class:`Incomparable` rather than
    being carried through as an opaque string that happens to compare unequal
    to the same port written the other way.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise Incomparable(category, f"a port must be a string or an int, got "
                                     f"{facts.safe_repr(value)}")
    text = str(value).strip()
    low, sep, high = text.partition("-")
    bounds = (low, high) if sep else (low, low)
    out = []
    for bound in bounds:
        bound = bound.strip()
        if not bound.isdigit():
            raise Incomparable(category, f"port spec {facts.safe_repr(text)} is neither "
                                         f"'<port>' nor '<low>-<high>'")
        number = int(bound)
        if not _PORT_MIN <= number <= _PORT_MAX:
            raise Incomparable(category, f"port {number} is outside "
                                         f"{_PORT_MIN}-{_PORT_MAX}")
        out.append(number)
    if out[0] > out[1]:
        raise Incomparable(category, f"port range {facts.safe_repr(text)} runs backwards")
    return (out[0], out[1])


def _ports(category: str, value: Any) -> frozenset[tuple[int, int]]:
    """A port list as a set of intervals. ``None`` and ``[]`` are ONE state
    here — both spell "every port" — and both normalise to the empty set."""
    if value is None:
        return frozenset()
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return frozenset({_port_interval(category, value)})
    if not isinstance(value, (list, tuple)):
        raise Incomparable(category, f"'ports' must be an array, got "
                                     f"{facts.safe_repr(value)}")
    return frozenset(_port_interval(category, item) for item in value)


def _layer4(category: str, value: Any) -> frozenset[tuple[str, frozenset[tuple[int, int]]]]:
    """The layer4 match as a frozenset of ``(protocol, {port intervals})``.

    The protocol is case-FOLDED: the provider applies a CaseDiffSuppress, so a
    rule written ``TCP`` and one written ``tcp`` are the same rule and a
    comparator that reports them as a change is reporting on spelling.
    """
    if value is None:
        return frozenset()
    if not isinstance(value, (list, tuple)):
        raise Incomparable(category, f"'layer4' must be an array, got "
                                     f"{facts.safe_repr(value)}")
    out = []
    for entry in value:
        if not isinstance(entry, Mapping):
            raise Incomparable(category, "each 'layer4' entry must be an object")
        unknown = sorted(set(str(k) for k in entry) - _LAYER4_KEYS)
        if unknown:
            raise Incomparable(category, f"layer4 entry carries key(s) {unknown} the "
                                         f"canonical protocol/ports form cannot hold; "
                                         f"normalising it would drop them silently")
        protocol = entry.get("protocol")
        if not isinstance(protocol, str) or not protocol.strip():
            raise Incomparable(category, "each 'layer4' entry needs a 'protocol' string")
        out.append((protocol.strip().casefold(), _ports(category, entry.get("ports"))))
    return frozenset(out)


def _priority(category: str, value: Any) -> Any:
    """``priority`` as an int. A rule's priority decides which rule wins, and
    ``"1000"`` from a terraform artifact is the same slot as ``1000`` from the
    API."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise Incomparable(category, "'priority' must be an int, got a bool")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise Incomparable(category, f"'priority' must be an int, got "
                                 f"{facts.safe_repr(value)}")


def _bool(category: str, name: str, value: Any) -> bool:
    """``disabled``/``preview`` as a bool. An ABSENT flag is ``False`` — that
    is the platform default, and one view omitting the key while the other
    writes ``false`` is not a difference."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().casefold() in ("true", "false"):
        return value.strip().casefold() == "true"
    raise Incomparable(category, f"{name!r} must be a bool, got "
                                 f"{facts.safe_repr(value)}")


def _normalise(spec: CategoryCompare, name: str, value: Any) -> Any:
    """ONE field's order-normalised, hashable form.

    Normalisation is driven by the field NAME at any depth: ``src_ip_ranges``
    is a set whether it sits on a rule or inside that rule's ``match``, and a
    ``layer4`` is a layer4 wherever it appears.
    """
    category = spec.category
    if name == "layer4":
        return _layer4(category, value)
    if name == "ports":
        return _ports(category, value)
    if name == "priority":
        return _priority(category, value)
    if name in _BOOL_FIELDS:
        return _bool(category, name, value)
    if name == "protocol":
        return (value.strip().casefold() if isinstance(value, str)
                else _frozen(spec, value, name))
    if name in spec.set_fields and isinstance(value, (list, tuple)):
        return frozenset(_frozen(spec, item) for item in value)
    if name in spec.ordered_fields and isinstance(value, (list, tuple)):
        return tuple(_frozen(spec, item) for item in value)
    return _frozen(spec, value, name)


def _frozen(spec: CategoryCompare, value: Any, name: str = "") -> Any:
    """A value taken whole: a mapping recurses BY NAME (so its fields get their
    own normalisation), a sequence keeps its order, and a scalar goes through
    :func:`gcp_grounding.claims.freeze`. ``name`` is carried for the refusal
    message only — an element of a collection has no name of its own."""
    if isinstance(value, Mapping):
        return _frozen_fields(spec, value)
    if isinstance(value, (list, tuple)):
        return tuple(_frozen(spec, item) for item in value)
    return _freeze(spec.category, name, value)


def _frozen_fields(spec: CategoryCompare, record: Mapping[str, Any]) -> tuple[Any, ...]:
    """One mapping's frozen form, at ANY depth and by the same two rules.

    A :data:`VOLATILE_IGNORED` field is dropped, because the form you compare
    must not carry the values that differ between two views of one UNCHANGED
    resource. A field whose normalised value is ``None`` is dropped too: a null
    field and an absent field are one state for a comparator, and keeping both
    spellings apart would make one view's explicit null a difference.
    """
    pairs: list[tuple[str, Any]] = []
    for name, value in record.items():
        name = str(name)
        if name in VOLATILE_IGNORED:
            continue
        frozen = _normalise(spec, name, value)
        if frozen is None:
            continue
        pairs.append((name, frozen))
    return _frozen_map(pairs)


def _expanded(spec: CategoryCompare, record: Mapping[str, Any]) -> Mapping[str, Any]:
    """``iam_bindings`` only: bindings → one record per role-member-condition
    triple.

    Two sources GROUP the same members differently — one two-member binding
    against two one-member bindings is the same policy — and a comparator that
    compares bindings as written reports that grouping as a change. Expanding
    to triples removes the grouping from the comparison entirely.

    An unrecognised key inside a binding makes the WHOLE record
    :class:`Incomparable` rather than partially compared: a partially compared
    IAM policy is a policy whose difference you did not see.
    """
    if spec.category != "iam_bindings" or "bindings" not in record:
        return record
    bindings = record.get("bindings")
    if bindings is None:
        return record
    if not isinstance(bindings, (list, tuple)):
        raise Incomparable(spec.category, f"'bindings' must be an array, got "
                                          f"{facts.safe_repr(bindings)}")
    triples: list[dict[str, Any]] = []
    for binding in bindings:
        if not isinstance(binding, Mapping):
            raise Incomparable(spec.category, "each 'bindings' entry must be an object")
        unknown = sorted(set(str(k) for k in binding) - _BINDING_KEYS)
        if unknown:
            raise Incomparable(
                spec.category,
                f"binding carries unrecognised key(s) {unknown}; the whole policy is "
                f"incomparable rather than partially compared, because a partially "
                f"compared IAM policy is a policy whose difference you did not see")
        role = binding.get("role")
        condition = binding.get("condition")
        members = binding.get("members")
        if members is None:
            members = ()
        if isinstance(members, str) or not isinstance(members, (list, tuple)):
            raise Incomparable(spec.category, f"binding 'members' must be an array, got "
                                              f"{facts.safe_repr(members)}")
        if not members:
            # A memberless binding grants nothing but is still something one
            # view says and the other does not; dropping it would be a silent
            # equality.
            triples.append({"role": role, "member": None, "condition": condition})
            continue
        for member in members:
            triples.append({"role": role, "member": member, "condition": condition})
    return dict(record, bindings=triples)


def comparable(category: str, record: Any) -> Any:
    """*record* as a deterministic, hashable, ORDER-NORMALISED form.

    Declared set fields become ``frozenset``s and declared ordered fields
    tuples, ``priority`` an int, ``disabled``/``preview`` bools, ``protocol``
    case-folded, ports intervals, and ``layer4`` a frozenset of
    ``(protocol, {intervals})`` pairs. ``iam_bindings`` are expanded to
    role-member-condition triples first.

    Two views of one UNCHANGED resource produce equal forms: a null field and
    an absent one are one state, and every :data:`VOLATILE_IGNORED` field is
    dropped — the form you compare must not carry the values that differ for
    reasons that are not about the estate.

    A flat vocabulary's record is its own name, and normalises to itself.
    Raises :class:`Incomparable` when normalisation itself cannot proceed.
    """
    spec = _spec(category)
    if not isinstance(record, Mapping):
        return _frozen(spec, record)
    return _frozen_fields(spec, _expanded(spec, record))


# -- comparison ---------------------------------------------------------------


def _classify(spec: CategoryCompare, name: str) -> tuple[str, str]:
    """``(severity, note)`` for one field name.

    Security first, then the two benign lists, then REFUSE: any other key is
    ``unmergeable`` and names itself. It is never silently equal and never
    guessed material, because a provider that adds a field must make a human
    look at it once.
    """
    if name in spec.security_fields:
        return MATERIAL, ""
    if name in spec.benign_fields:
        return BENIGN, spec.benign_fields[name]
    if name in BENIGN_REPORTED:
        return BENIGN, ""
    return UNMERGEABLE, (f"field {name!r} is classified by no list for category "
                         f"{spec.category!r}; an unclassified field is never silently "
                         f"equal and never guessed material")


def _field_diffs(spec: CategoryCompare, left: Mapping[str, Any],
                 right: Mapping[str, Any], prefix: str, subkey: str,
                 skip: frozenset[str]) -> list[FieldDiff]:
    """The union-of-keys walk over one record (or one subrecord)."""
    diffs: list[FieldDiff] = []
    names = {str(k) for k in left} | {str(k) for k in right}
    for name in sorted(names):
        if name in VOLATILE_IGNORED or name in skip:
            continue
        severity, note = _classify(spec, name)
        path_field = f"{prefix}{name}"
        if not prefix and name in spec.subrecord_keys:
            nested = _subrecord_diffs(spec, name, left.get(name), right.get(name))
            if nested is not None:
                diffs.extend(nested)
                continue
        left_value = _normalise(spec, name, left.get(name))
        right_value = _normalise(spec, name, right.get(name))
        if severity == UNMERGEABLE:
            # Emitted even when the two values are equal: "recognised" is what
            # makes a field safely comparable, and this one is not recognised.
            diffs.append(FieldDiff(path_field, subkey, UNMERGEABLE,
                                   left_value, right_value, note))
            continue
        if left_value != right_value:
            diffs.append(FieldDiff(path_field, subkey, severity,
                                   left_value, right_value, note))
    return diffs


def _entries(spec: CategoryCompare, field: str, value: Any
             ) -> list[tuple[Any, int, Any]] | None:
    """``[(identity, index, element)]`` for one side of a subrecord collection,
    or ``None`` when the value is not a collection at all (the caller then
    falls back to comparing the field as one value).

    An element that does not carry the aligning key is aligned by its WHOLE
    value, never by position: aligning by position would pair two unrelated
    rules and report the difference between them as a change to one.
    """
    key_field = spec.subrecord_keys[field]
    if value is None:
        return []
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, (list, tuple)):
        return None
    out: list[tuple[Any, int, Any]] = []
    for index, element in enumerate(value):
        if key_field == BY_INDEX:
            identity: Any = ("index", index)
        elif (key_field != BY_VALUE and isinstance(element, Mapping)
              and key_field in element):
            identity = ("key", _normalise(spec, key_field, element[key_field]))
        else:
            identity = ("value", _frozen(spec, element))
        out.append((identity, index, element))
    return out


def _subrecord_diffs(spec: CategoryCompare, field: str, left: Any, right: Any
                     ) -> list[FieldDiff] | None:
    """Element-wise comparison of one subrecord collection, aligned by the
    category's subrecord key. An element present on ONE side only is a MATERIAL
    diff whose missing side renders as ``None``."""
    left_entries = _entries(spec, field, left)
    right_entries = _entries(spec, field, right)
    if left_entries is None or right_entries is None:
        return None

    pending: dict[Any, list[tuple[int, Any]]] = {}
    for identity, index, element in left_entries:
        pending.setdefault(identity, []).append((index, element))
    pairs: list[tuple[int, Any, Any]] = []
    for identity, index, element in right_entries:
        queue = pending.get(identity)
        if queue:
            left_index, left_element = queue.pop(0)
            pairs.append((left_index, left_element, element))
        else:
            pairs.append((index, None, element))
    for queue in pending.values():
        for index, element in queue:
            pairs.append((index, element, None))
    pairs.sort(key=lambda pair: (pair[0], pair[1] is None, pair[2] is None))

    diffs: list[FieldDiff] = []
    for index, left_element, right_element in pairs:
        subkey = str(index)
        if left_element is None or right_element is None:
            diffs.append(FieldDiff(
                field, subkey, MATERIAL,
                None if left_element is None else _frozen(spec, left_element),
                None if right_element is None else _frozen(spec, right_element)))
            continue
        if isinstance(left_element, Mapping) and isinstance(right_element, Mapping):
            diffs.extend(_field_diffs(spec, left_element, right_element,
                                      f"{field}.", subkey, frozenset()))
            continue
        left_value = _frozen(spec, left_element)
        right_value = _frozen(spec, right_element)
        if left_value != right_value:
            diffs.append(FieldDiff(field, subkey, MATERIAL, left_value, right_value))
    return diffs


def _perimeter_diff(spec: CategoryCompare, left: Mapping[str, Any],
                    right: Mapping[str, Any]) -> FieldDiff | None:
    """THE PERIMETER RULE. A VPC-SC ``status`` block is ENFORCED and a ``spec``
    block is DRY-RUN — the naming is genuinely counterintuitive, which is why
    this comment exists. The two are compared status-to-status and
    spec-to-spec only; when one view carries only ``spec`` and the other only
    ``status`` there is nothing to compare, and the comparator says so instead
    of pairing them, because a silently paired dry-run perimeter reads as
    enforced."""
    if spec.category != "vpc_sc_perimeters":
        return None
    sides = {}
    for name, record in (("left", left), ("right", right)):
        sides[name] = (record.get("status") is not None, record.get("spec") is not None)
    left_status, left_spec = sides["left"]
    right_status, right_spec = sides["right"]
    cross = ((left_spec and not left_status and right_status and not right_spec)
             or (left_status and not left_spec and right_spec and not right_status))
    if not cross:
        return None
    logger.debug("perimeter comparison refused: one view carries only 'spec' and the "
                 "other only 'status'")
    return FieldDiff("status/spec", "", UNMERGEABLE,
                     _frozen(spec, left.get("spec") if left_spec else left.get("status")),
                     _frozen(spec, right.get("spec") if right_spec else right.get("status")),
                     PERIMETER_CROSS_PAIR)


def compare(category: str, left: Any, right: Any) -> tuple[FieldDiff, ...]:
    """Every field on which two views of ONE resource disagree.

    The walk is over the UNION of both records' keys, so a field only one side
    carries is compared against ``None`` rather than skipped. A field in
    :data:`VOLATILE_IGNORED` yields NO diff at all; a security field yields
    ``material``; a benign one yields ``benign``; and any other key yields
    ``unmergeable`` naming the field.

    Comparing against a ``None`` document yields no diffs: a view that does not
    exist disagrees with nothing, and the absence is the caller's answer to
    report (as ``baseline:new``), not a wall of field differences.
    """
    spec = _spec(category)
    if left is None or right is None:
        return ()
    if not isinstance(left, Mapping) and not isinstance(right, Mapping):
        left_value = _frozen(spec, left)
        right_value = _frozen(spec, right)
        if left_value == right_value:
            return ()
        # A flat vocabulary's record IS its name, so a difference is a
        # difference of identity — material, and never anything softer.
        return (FieldDiff("name", "", MATERIAL, left_value, right_value,
                          spec.note or _FLAT_NOTE),)
    if not isinstance(left, Mapping) or not isinstance(right, Mapping):
        raise Incomparable(category, "one view is a record and the other a bare name; "
                                     "there is no field-by-field comparison between them")
    left = _expanded(spec, left)
    right = _expanded(spec, right)
    diffs: list[FieldDiff] = []
    skip: frozenset[str] = frozenset()
    perimeter = _perimeter_diff(spec, left, right)
    if perimeter is not None:
        # The refusal REPLACES both blocks' diffs: reporting the missing
        # 'status' and the missing 'spec' as two ordinary differences would
        # bury the one thing that matters.
        diffs.append(perimeter)
        skip = frozenset({"status", "spec"})
    diffs.extend(_field_diffs(spec, left, right, "", "", skip))
    return tuple(diffs)
