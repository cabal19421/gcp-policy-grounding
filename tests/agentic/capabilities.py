"""BEHAVIOURAL capability probes: can the real code decide this family, or not?

A capability is LIVE only when the gate, run for real and fully offline,
DECIDES a known-BAD input **and** stays QUIET on a known-GOOD near-twin. Both
halves are required and neither alone is sufficient:

* The BAD half kills the shapes a presence check never noticed — the module
  deleted, its ``DOCUMENT_CHECKS`` tuple emptied, its ``PAIR_CHECKS`` map
  emptied, a verdict kind renamed, a claim kind dropped from the vocabulary.
  Each of those leaves the file on disk and the name in the tuple, so
  ``find_spec`` and ``"kind" in KINDS`` both keep answering True while nothing
  can block.
* The GOOD half is what makes a probe NON-FAKEABLE. A check that always
  grounds, a subset check with a hardcoded result, a public-principal arm
  neutered to ``grounded``, a check that always contradicts: a one-sided probe
  calls every one of those live. Requiring the near-twin to stay quiet on the
  family's own channel means a rubber stamp is measured as DEAD, and its
  family loudly skips instead of collecting a green from a stamp.

:func:`probe` therefore NEVER consults the presence of the module under test.
It calls the real :func:`gcp_grounding.preflight.ground_policy` in process,
twice, with no subprocess and no network, so it costs nothing against the
suite's subprocess budget. "The file is gone" and "the check is gutted" both
come out the same way: ``live=False`` with a :attr:`Probe.reason` carrying the
MEASURED report, so a skip says what was actually seen rather than what was
assumed.

Importable at DECORATOR time exactly like :mod:`tests.agentic.env` — which is
why this module deliberately does NOT import ``env``: ``env``'s domain probes
are thin delegates to this one, and the dependency runs that way round only.
Every probe is computed inside a ``try``/``except`` and memoized once per
session; nothing here raises, at import or after it.

A CAPABILITY OWNS ITS OWN FIXTURES. Whatever a family's bad input needs — an
estate snapshot category, a resource the overlay carries, a baseline document
— belongs in that capability's :attr:`Capability.bad` callable and nowhere
else. That is the direct replacement for the habit of ANDing an unrelated
``HAVE_ESTATE_CATEGORY`` onto a family's gate: a fixture that cannot be built
degrades to a ``live=False`` probe naming the failure, which is the same loud
skip as every other dead capability, rather than a second flag no reader can
attribute to a family.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable

from gcp_grounding.knowledge import GcpSnapshot

__all__ = [
    "ARMOR",
    "CAPABILITIES",
    "Capability",
    "FIREWALL",
    "HIER_FIREWALL",
    "IAM_EXISTENCE",
    "ORG_CONSTRAINT_VALUE",
    "ORG_ENFORCEMENT",
    "Probe",
    "PUBLIC_PRINCIPAL",
    "TF_CLAIMS",
    "VPCSC",
    "probe",
]

_FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "gcp"
_ESTATE_SNAPSHOT = _FIXTURES / "agentic_snapshot.json"
_ESTATE_OVERLAY = _FIXTURES / "agentic_estate_overlay.json"

#: The two statuses that are FINDINGS. A good near-twin may carry neither on
#: its family's own channel; ``unverified`` is fine there — an abstention is an
#: honest answer, and a capability that abstains on the good twin while
#: deciding the bad one is working exactly as intended.
_FINDING_STATUSES = ("ungrounded", "contradicted")


@dataclass(frozen=True)
class Probe:
    """The measurement: is this capability live, and — when it is not — the
    verbatim text a ``skipif`` shows the reader."""

    live: bool
    #: Empty when live. Otherwise the skip text, naming the capability, its
    #: family and what the two runs actually produced.
    reason: str = ""


@dataclass(frozen=True)
class Capability:
    """One family's ability to decide, expressed as two inputs and a verdict.

    *bad* and *good* each return ``(document, snapshot)`` — the pair
    :func:`~gcp_grounding.preflight.ground_policy` takes. They are callables,
    not constants, so a fixture that needs a snapshot category this checkout
    cannot load raises inside the probe and degrades to a named skip instead
    of breaking collection.
    """

    name: str
    #: Key into :data:`tests.agentic.asserts.FAMILY_KINDS`.
    family: str
    #: The verdict kinds this capability OWNS — a subset of its family's
    #: entry, and disjoint from :data:`~tests.agentic.asserts.INCIDENTAL_KINDS`
    #: so a free ``grounded resource_type`` can never read as a live domain.
    kinds: frozenset[str]
    bad: Callable[[], tuple[Any, GcpSnapshot]]
    good: Callable[[], tuple[Any, GcpSnapshot]]
    #: The status the BAD input must produce on one of :attr:`kinds`.
    decided: str = "contradicted"
    #: ``(module, attribute)`` pairs a mutation test empties to gut this
    #: capability's dispatch — the check tuples and claim maps the real code
    #: dispatches through. NOT consulted by :func:`probe`: a probe that read
    #: this would be a presence check wearing a data structure. Empty where
    #: this checkout has no such table yet; the task that lands the family's
    #: checks fills it in.
    guts: tuple[tuple[str, str], ...] = ()


# -- the probe ----------------------------------------------------------------


@lru_cache(maxsize=None)
def probe(cap: Capability) -> Probe:
    """Measure *cap* — twice through the real gate, memoized for the session.

    Never raises. A fixture that cannot be built, a snapshot that will not
    load, an extractor that explodes: each is caught and reported as a
    ``live=False`` probe naming the failure, because a capability whose own
    inputs cannot be constructed is a capability that cannot be trusted to
    decide anything.
    """
    owned = ", ".join(sorted(cap.kinds))

    bad, error = _ground(cap.bad)
    if error is not None:
        return Probe(False, (
            f"{cap.name}: the bad {cap.family} input could not be grounded at "
            f"all ({error}) — nothing was measured, so this capability is not "
            f"live"))
    decided = [v for v in bad if v["kind"] in cap.kinds
               and v["status"] == cap.decided]
    if not decided:
        return Probe(False, (
            f"{cap.name}: the bad {cap.family} input produced no "
            f"{cap.decided} verdict on the kinds this family owns ({owned}) — "
            f"the report held {_render(bad)}"))

    good, error = _ground(cap.good)
    if error is not None:
        return Probe(False, (
            f"{cap.name}: the good {cap.family} near-twin could not be "
            f"grounded at all ({error}) — the bad input was decided, but a "
            f"decision nothing can be compared against is not evidence"))
    leaked = [v for v in good if v["kind"] in cap.kinds
              and v["status"] in _FINDING_STATUSES]
    if leaked:
        return Probe(False, (
            f"{cap.name}: the good {cap.family} near-twin fired too, on the "
            f"kinds this family owns ({owned}) — a check that decides the same "
            f"way on both inputs is a rubber stamp, not a capability — the "
            f"good report held {_render(good)}"))
    return Probe(True)


def _ground(fixture: Callable[[], tuple[Any, GcpSnapshot]]):
    """→ (verdicts as plain dicts, error). Exactly one is meaningful.

    The import of ``preflight`` lives here rather than at module scope so that
    a broken gate degrades this module to all-dead probes instead of breaking
    collection of every suite that imports it at decorator time.
    """
    try:
        from gcp_grounding import preflight

        document, snapshot = fixture()
        report = preflight.ground_policy(document, snapshot)
        return [{"status": v.status, "kind": v.kind, "target": v.target,
                 "message": v.message} for v in report.verdicts], None
    except Exception as exc:  # never raises: a dead probe is the answer
        return None, f"{type(exc).__name__}: {exc}"


def _render(verdicts: Iterable[dict]) -> str:
    """The measured verdicts, compactly, for a skip reason."""
    seen = [f"{v['status']} {v['kind']} {v['target']!r}" for v in verdicts]
    if not seen:
        return "no verdicts at all"
    if len(seen) == 1:
        return f"only {seen[0]}"
    return "; ".join(seen)


# -- shared fixture material --------------------------------------------------


@lru_cache(maxsize=1)
def estate_snapshot() -> GcpSnapshot:
    """The estate snapshot the capability fixtures ground against.

    The overlay's domain categories (firewall rules, perimeters, armor
    policies, org policies) are merged in when
    :meth:`~gcp_grounding.knowledge.GcpSnapshot.from_dict` accepts them and
    dropped when it does not — this checkout's ``from_dict`` rejects unknown
    top-level keys, and a capability that needs one of those categories should
    measure as dead here, loudly, rather than have every unrelated family gated
    on a shared ``HAVE_ESTATE_CATEGORY`` flag nobody can attribute.
    """
    base = json.loads(_ESTATE_SNAPSHOT.read_text(encoding="utf-8"))
    merged = dict(base)
    merged.update(json.loads(_ESTATE_OVERLAY.read_text(encoding="utf-8")))
    try:
        return GcpSnapshot.from_dict(merged)
    except ValueError:
        return GcpSnapshot.from_dict(base)


def _tf_plan(address: str, rtype: str, values: dict) -> dict:
    """One-resource ``terraform show -json`` plan output."""
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.5",
        "planned_values": {"root_module": {"resources": [{
            "address": address,
            "mode": "managed",
            "type": rtype,
            "name": address.split(".", 1)[-1],
            "provider_name": "registry.terraform.io/hashicorp/google",
            "values": values,
        }]}},
    }


def _iam_policy(role: str, member: str) -> dict:
    return {"version": 3, "etag": "BwYn8x2Qb0c=",
            "bindings": [{"role": role, "members": [member]}]}


def _org_policy_v2(constraint_id: str, rule: dict) -> dict:
    return {"name": f"projects/acme-prod/policies/{constraint_id}",
            "spec": {"rules": [rule]}}


def _firewall(source_ranges: list[str]) -> dict:
    return _tf_plan("google_compute_firewall.ssh", "google_compute_firewall", {
        "name": "ssh-ingress",
        "network": "projects/acme-prod/global/networks/prod-vpc",
        "direction": "INGRESS", "priority": 900, "disabled": False,
        "source_ranges": source_ranges, "target_tags": ["bastion"],
        "allow": [{"protocol": "tcp", "ports": ["22"]}],
    })


def _firewall_policy_rule(src_ip_ranges: list[str]) -> dict:
    return _tf_plan("google_compute_firewall_policy_rule.rdp",
                    "google_compute_firewall_policy_rule", {
                        "firewall_policy": ("organizations/123456789012/locations/"
                                            "global/firewallPolicies/org-baseline"),
                        "action": "allow", "direction": "INGRESS",
                        "priority": 100, "disabled": False,
                        "match": [{"src_ip_ranges": src_ip_ranges,
                                   "layer4_config": [{"ip_protocol": "tcp",
                                                      "ports": ["3389"]}]}],
                    })


def _security_policy(src_ip_ranges: list[str]) -> dict:
    return _tf_plan("google_compute_security_policy.edge",
                    "google_compute_security_policy", {
                        "name": "acme-edge-waf",
                        "rule": [{
                            "action": "allow", "priority": 100, "preview": False,
                            "match": [{"versioned_expr": "SRC_IPS_V1",
                                       "config": [{"src_ip_ranges": src_ip_ranges}]}],
                        }],
                    })


def _perimeter(restricted_services: list[str]) -> dict:
    return {
        "name": "accessPolicies/987654321/servicePerimeters/acme_prod",
        "title": "acme_prod",
        "perimeterType": "PERIMETER_TYPE_REGULAR",
        "status": {
            "resources": ["projects/111111111111"],
            "restrictedServices": restricted_services,
            "accessLevels": ["accessPolicies/987654321/accessLevels/trusted_corp"],
            "ingressPolicies": [],
            "egressPolicies": [],
        },
    }


def _org_enforcement(enforce: bool) -> dict:
    return _org_policy_v2("iam.disableServiceAccountKeyCreation",
                          {"enforce": enforce})


# -- the declared capabilities ------------------------------------------------
#
# Two of these — IAM_EXISTENCE and ORG_CONSTRAINT_VALUE — are decided by checks
# this checkout already ships, and TF_CLAIMS by the terraform extractor it
# already ships. They are not decoration: they are the only capabilities whose
# rubber-stamp and gutted-dispatch mutants can be EXECUTED here, and
# tests/test_gcp_capabilities.py executes them. Without at least one live
# capability every assertion about "the probe went dead" would be satisfied by
# a probe that was never alive.

IAM_EXISTENCE = Capability(
    name="iam_existence",
    family="iam",
    kinds=frozenset({"role"}),
    bad=lambda: (_iam_policy("roles/bigquery.reader",
                             "group:data-eng@acme.example"), estate_snapshot()),
    good=lambda: (_iam_policy("roles/bigquery.dataViewer",
                              "group:data-eng@acme.example"), estate_snapshot()),
    decided="ungrounded",
    guts=(("gcp_grounding.preflight", "EXISTENCE_KINDS"),),
)

TF_CLAIMS = Capability(
    name="tf_claims",
    family="iam",
    kinds=frozenset({"role"}),
    bad=lambda: (_tf_plan("google_project_iam_binding.reader",
                          "google_project_iam_binding",
                          {"role": "roles/bigquery.reader",
                           "members": ["group:data-eng@acme.example"]}),
                 estate_snapshot()),
    good=lambda: (_tf_plan("google_project_iam_binding.reader",
                           "google_project_iam_binding",
                           {"role": "roles/bigquery.dataViewer",
                            "members": ["group:data-eng@acme.example"]}),
                  estate_snapshot()),
    decided="ungrounded",
    guts=(("gcp_grounding.tf_claims", "_EXTRACTORS"),),
)

ORG_CONSTRAINT_VALUE = Capability(
    name="org_constraint_value",
    family="orgpolicy",
    kinds=frozenset({"constraint", "constraint_value"}),
    # A boolean-typed constraint used list-typed is a contradiction the
    # snapshot decides on its own; the near-twin uses it boolean-typed.
    bad=lambda: (_org_policy_v2("iam.disableServiceAccountKeyCreation",
                                {"values": {"allowedValues": ["C01acme42"]}}),
                 estate_snapshot()),
    good=lambda: (_org_policy_v2("iam.disableServiceAccountKeyCreation",
                                 {"enforce": True}), estate_snapshot()),
    guts=(("gcp_grounding.claims", "_V2_LIST_KEYS"),),
)

FIREWALL = Capability(
    name="firewall",
    family="network",
    kinds=frozenset({"firewall_rule", "firewall_exposure", "firewall_pair"}),
    # tcp/22 opened to the whole internet, against an estate whose only ssh
    # rule is scoped to 10/8. The near-twin is that same estate rule.
    bad=lambda: (_firewall(["0.0.0.0/0"]), estate_snapshot()),
    good=lambda: (_firewall(["10.0.0.0/8"]), estate_snapshot()),
)

HIER_FIREWALL = Capability(
    name="hier_firewall",
    family="network",
    kinds=frozenset({"firewall_policy_rule", "hfw_order", "hfw_shadow",
                     "hfw_widen", "hfw_effect"}),
    # priority 100 re-opens tcp/3389, which org-baseline denies at 1000.
    bad=lambda: (_firewall_policy_rule(["0.0.0.0/0"]), estate_snapshot()),
    good=lambda: (_firewall_policy_rule(["10.0.0.0/8"]), estate_snapshot()),
)

ARMOR = Capability(
    name="armor",
    family="network",
    kinds=frozenset({"security_policy_rule", "armor_rule", "armor_bypass",
                     "armor_default", "armor_expr", "armor_priority"}),
    # An allow at priority 100 in front of the captured deny(403) at 1000.
    bad=lambda: (_security_policy(["0.0.0.0/0"]), estate_snapshot()),
    good=lambda: (_security_policy(["10.0.0.0/8"]), estate_snapshot()),
)

VPCSC = Capability(
    name="vpcsc",
    family="vpcsc",
    kinds=frozenset({"perimeter_config", "perimeter_ingress", "perimeter_egress",
                     "vpcsc_protection", "vpcsc_dry_run", "vpcsc_ingress",
                     "vpcsc_egress"}),
    # Dropping storage.googleapis.com unprotects a service the captured
    # perimeter restricts; the near-twin is the perimeter as captured.
    bad=lambda: (_perimeter(["bigquery.googleapis.com"]), estate_snapshot()),
    good=lambda: (_perimeter(["storage.googleapis.com",
                              "bigquery.googleapis.com"]), estate_snapshot()),
)

PUBLIC_PRINCIPAL = Capability(
    name="public_principal",
    family="iam",
    kinds=frozenset({"public_principal", "iam_public"}),
    bad=lambda: (_iam_policy("roles/editor", "allUsers"), estate_snapshot()),
    good=lambda: (_iam_policy("roles/editor", "group:platform-sre@acme.example"),
                  estate_snapshot()),
)

ORG_ENFORCEMENT = Capability(
    name="org_enforcement",
    family="orgpolicy",
    kinds=frozenset({"constraint_enforcement", "org_enforcement"}),
    # The estate enforces this constraint at projects/acme-prod; setting it
    # unenforced is the regression. The near-twin leaves it enforced.
    bad=lambda: (_org_enforcement(False), estate_snapshot()),
    good=lambda: (_org_enforcement(True), estate_snapshot()),
)

#: Every declared capability, by name.
CAPABILITIES: dict[str, Capability] = {
    cap.name: cap for cap in (
        IAM_EXISTENCE, TF_CLAIMS, ORG_CONSTRAINT_VALUE, FIREWALL,
        HIER_FIREWALL, ARMOR, VPCSC, PUBLIC_PRINCIPAL, ORG_ENFORCEMENT,
    )
}
