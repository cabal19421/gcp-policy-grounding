"""Claim extraction: VPC firewall rules → grounding claims.

Pure parsing — no snapshot, no solver — mirroring :mod:`gcp_grounding.claims`:
anything that does not resolve unambiguously is skipped or made explicitly
undecidable, never guessed at. Two spellings of the same object are handled: the
Compute REST resource (``kind == "compute#firewall"``) and the Terraform
``google_compute_firewall`` resource inside a ``terraform show -json`` plan.

The normalized firewall rule mapping
====================================

Both spellings collapse to ONE normalized mapping — the contract shared, by
identical field names, with :func:`packet.rule_match`, :mod:`fw_estate` and the
``snapshot.firewall_rules`` records. :func:`normalize_rest` and
:func:`normalize_tf` produce it; :func:`~gcp_grounding.claims.Claim.of` carries
the whole thing in the frozen ``payload`` of the one ``firewall_rule`` claim, so
a checker reads it back with :meth:`~gcp_grounding.claims.Claim.fields`.

- ``name`` — the rule's name.
- ``network`` — the VPC network, canonicalized to
  ``projects/<p>/global/networks/<n>`` when resolvable (see
  :func:`normalize_network`), otherwise the value as written.
- ``direction`` — ``INGRESS`` (default) or ``EGRESS``.
- ``action`` — ``allow`` or ``deny``.
- ``priority`` — integer rule priority (default ``1000``).
- ``disabled`` — whether the rule is disabled (default ``False``).
- ``source_ranges`` / ``destination_ranges`` — CIDR strings.
- ``source_tags`` / ``target_tags`` — network-tag names.
- ``source_service_accounts`` / ``target_service_accounts`` — service-account
  identifiers, as written.
- ``layer4`` — a list of ``{"protocol": <str>, "ports": [<str>, ...]}`` objects
  (an empty ``ports`` list means "all ports for this protocol").

An undecidable shape does not drop the rule: when a required field is missing or
wrong-typed (no ``network``, no allow/deny entry, a non-integer ``priority``, a
``direction`` other than ``INGRESS``/``EGRESS``) the mapping is emitted anyway
with the broken field omitted and an extra ``"unsupported": "<reason>"`` key.
Downstream checks treat any payload carrying ``unsupported`` as an automatic
``unverified`` naming the reason, so the rule is never silently dropped from a
set comparison.

Tags: two halves of one rule
============================

A ``source_tags`` entry names instances the rule expects to *already exist*, so
each yields one ``network_tag_ref`` claim — grounded later against the captured
tag vocabulary, where a miss is a presence-only ``unverified`` with a did-you-mean,
never a block.

A ``target_tags`` entry is the opposite: it *defines* the tag by naming the
instances this rule will apply to. The tag comes into existence by being written
here (and on the instances); no API could have listed it first. This is the
resource-being-created precedent applied to the one GCP object with no
registration step. Emitting a ``network_tag_ref`` for it would push a brand-new
tag into a captured-but-necessarily-partial vocabulary and produce a false
``ungrounded`` — a block on a completely legitimate change, the cry-wolf failure
the false-positive discipline forbids. So ``target_tags`` yield **no**
``network_tag_ref``.

Claims emitted per rule
=======================

- ``network_ref`` — for the normalized network; skipped when unnormalizable.
- ``network_tag_ref`` — one per ``source_tags`` entry ONLY (see above).
- ``service_account_ref`` — one per ``source_service_accounts`` and
  ``target_service_accounts`` entry, in bare-email form (a leading
  ``serviceAccount:`` is stripped).
- ``firewall_rule`` — exactly one, whose ``value`` is the rule name (or, for a
  Terraform rule whose name is unresolved, the resource address) and whose
  ``location`` is the json path (``name``) or the tf address; the whole
  normalized mapping travels in its ``payload``.

No existence claim is emitted for the rule's own name — the rule is being created.

Wiring: :data:`DOCUMENT_EXTRACTORS` and :data:`TF_EXTRACTORS` are the module-level
tables the registry (:func:`gcp_grounding.registry.document_extractor`) and the
terraform hook (:func:`gcp_grounding.registry.tf_extractors`) discover lazily,
with no edit elsewhere.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .claims import Claim
from .core.log import get_logger
from .tf_claims import _blocks

logger = get_logger(__name__)

__all__ = [
    "detect_kind", "normalize_network", "normalize_rest", "normalize_tf",
    "firewall_rule_claims", "DOCUMENT_EXTRACTORS", "TF_EXTRACTORS",
]

#: The Compute REST resource marker (``kind`` field of a firewall document).
_REST_KIND = "compute#firewall"

#: The one self-link prefix :func:`normalize_network` strips.
_COMPUTE_V1_PREFIX = "https://www.googleapis.com/compute/v1/"

#: IAM member-syntax prefix a service-account identifier may carry; stripped so
#: the ``service_account_ref`` claim value is a bare email.
_SA_PREFIX = "serviceAccount:"

#: REST spelling of the two service-account list fields, keyed by normalized name.
_REST_SA_FIELDS = {
    "source_service_accounts": "sourceServiceAccounts",
    "target_service_accounts": "targetServiceAccounts",
}


# -- network canonicalization -------------------------------------------------


def normalize_network(value: Any) -> str | None:
    """Canonicalize a firewall rule's ``network`` to
    ``projects/<p>/global/networks/<n>`` — or None when it cannot be resolved.

    Strips a leading ``https://www.googleapis.com/compute/v1/`` self-link prefix,
    accepts an already-canonical ``projects/<p>/global/networks/<n>``, and
    returns None for a bare name or an unresolvable interpolation. A None result
    means the ``network_ref`` claim is skipped, not invented.
    """
    if not isinstance(value, str) or not value:
        return None
    candidate = value
    if candidate.startswith(_COMPUTE_V1_PREFIX):
        candidate = candidate[len(_COMPUTE_V1_PREFIX):]
    parts = candidate.split("/")
    if (len(parts) == 5 and parts[0] == "projects" and parts[1]
            and parts[2] == "global" and parts[3] == "networks" and parts[4]):
        return candidate
    return None


# -- normalization: REST and Terraform → the one mapping ----------------------


def _str_list(value: Any) -> list[str]:
    """The string entries of a list value, in order; ``[]`` for anything else."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _layer4(protoports: list[Mapping[str, Any]], proto_key: str) -> list[dict]:
    """Normalize protocol/ports objects to ``{"protocol", "ports"}`` entries.

    *proto_key* is ``IPProtocol`` (REST) or ``protocol`` (Terraform). An entry
    without a protocol name is skipped rather than guessed at."""
    out: list[dict] = []
    for entry in protoports:
        if not isinstance(entry, Mapping):
            continue
        protocol = entry.get(proto_key)
        if not isinstance(protocol, str) or not protocol:
            continue
        out.append({"protocol": protocol, "ports": _str_list(entry.get("ports"))})
    return out


def _apply_network(normalized: dict, raw: Any, reasons: list[str]) -> None:
    if not isinstance(raw, str) or not raw:
        reasons.append("network is missing or not a string")
        return
    canonical = normalize_network(raw)
    normalized["network"] = canonical if canonical is not None else raw


def _apply_direction(normalized: dict, raw: Any, reasons: list[str]) -> None:
    if raw is None:
        normalized["direction"] = "INGRESS"
    elif isinstance(raw, str) and raw in ("INGRESS", "EGRESS"):
        normalized["direction"] = raw
    else:
        reasons.append(f"direction {raw!r} is not INGRESS or EGRESS")


def _apply_priority(normalized: dict, raw: Any, reasons: list[str]) -> None:
    if raw is None:
        normalized["priority"] = 1000
    elif isinstance(raw, int) and not isinstance(raw, bool):
        normalized["priority"] = raw
    else:
        reasons.append(f"priority {raw!r} is not an integer")


def _apply_action(normalized: dict, allow_entries: list, deny_entries: list,
                  proto_key: str, reasons: list[str]) -> None:
    if allow_entries and deny_entries:
        reasons.append("rule carries both allow and deny entries")
        return
    if allow_entries:
        action, entries = "allow", allow_entries
    elif deny_entries:
        action, entries = "deny", deny_entries
    else:
        reasons.append("no allow or deny entry")
        return
    layer4 = _layer4(entries, proto_key)
    if not layer4:
        reasons.append("no allow or deny entry")
        return
    normalized["action"] = action
    normalized["layer4"] = layer4


def normalize_rest(doc: Any) -> dict | None:
    """Normalize a Compute REST firewall document (``compute#firewall``).

    Returns the normalized mapping (see the module docstring), or None when
    *doc* is not a mapping. An undecidable field adds an ``"unsupported"`` key
    and is omitted; the rule is never dropped."""
    if not isinstance(doc, Mapping):
        return None
    reasons: list[str] = []
    normalized: dict[str, Any] = {}
    name = doc.get("name")
    normalized["name"] = name if isinstance(name, str) and name else ""
    _apply_network(normalized, doc.get("network"), reasons)
    _apply_direction(normalized, doc.get("direction"), reasons)
    allowed = doc.get("allowed") if isinstance(doc.get("allowed"), list) else []
    denied = doc.get("denied") if isinstance(doc.get("denied"), list) else []
    _apply_action(normalized, allowed, denied, "IPProtocol", reasons)
    _apply_priority(normalized, doc.get("priority"), reasons)
    normalized["disabled"] = doc.get("disabled") is True
    normalized["source_ranges"] = _str_list(doc.get("sourceRanges"))
    normalized["destination_ranges"] = _str_list(doc.get("destinationRanges"))
    normalized["source_tags"] = _str_list(doc.get("sourceTags"))
    normalized["target_tags"] = _str_list(doc.get("targetTags"))
    normalized["source_service_accounts"] = _str_list(doc.get("sourceServiceAccounts"))
    normalized["target_service_accounts"] = _str_list(doc.get("targetServiceAccounts"))
    if reasons:
        normalized["unsupported"] = "; ".join(reasons)
    return normalized


def normalize_tf(values: Any) -> dict | None:
    """Normalize a ``google_compute_firewall`` resource's planned values.

    Snake_case fields; ``allow``/``deny`` are repeated blocks read via
    :func:`gcp_grounding.tf_claims._blocks`, each with ``protocol``/``ports``.
    ``name`` is None when it is not a resolvable string (a known-after-apply
    interpolation); the caller supplies the resource address as the rule's value
    in that case. Returns None when *values* is not a mapping."""
    if not isinstance(values, Mapping):
        return None
    reasons: list[str] = []
    normalized: dict[str, Any] = {}
    name = values.get("name")
    normalized["name"] = name if isinstance(name, str) and name else None
    _apply_network(normalized, values.get("network"), reasons)
    _apply_direction(normalized, values.get("direction"), reasons)
    allow_entries = [block for block, _ in _blocks(values.get("allow"), "allow")]
    deny_entries = [block for block, _ in _blocks(values.get("deny"), "deny")]
    _apply_action(normalized, allow_entries, deny_entries, "protocol", reasons)
    _apply_priority(normalized, values.get("priority"), reasons)
    normalized["disabled"] = values.get("disabled") is True
    normalized["source_ranges"] = _str_list(values.get("source_ranges"))
    normalized["destination_ranges"] = _str_list(values.get("destination_ranges"))
    normalized["source_tags"] = _str_list(values.get("source_tags"))
    normalized["target_tags"] = _str_list(values.get("target_tags"))
    normalized["source_service_accounts"] = _str_list(values.get("source_service_accounts"))
    normalized["target_service_accounts"] = _str_list(values.get("target_service_accounts"))
    if reasons:
        normalized["unsupported"] = "; ".join(reasons)
    return normalized


# -- claim emission -----------------------------------------------------------


def _reference_claims(normalized: Mapping[str, Any], *,
                      network_location: str,
                      source_tag_location: Callable[[int], str],
                      sa_location: Callable[[str, int], str]) -> list[Claim]:
    """The existence-reference claims a normalized rule makes: one
    ``network_ref`` (when the network canonicalizes), one ``network_tag_ref``
    per ``source_tags`` entry (never ``target_tags``), and one
    ``service_account_ref`` per source/target service account (bare-email)."""
    claims: list[Claim] = []
    canonical = normalize_network(normalized.get("network"))
    if canonical is not None:
        claims.append(Claim("network_ref", canonical, network_location))
    for i, tag in enumerate(normalized.get("source_tags", ())):
        if isinstance(tag, str) and tag:
            claims.append(Claim("network_tag_ref", tag, source_tag_location(i)))
    for field in ("source_service_accounts", "target_service_accounts"):
        for i, account in enumerate(normalized.get(field, ())):
            if not isinstance(account, str) or not account:
                continue
            bare = account[len(_SA_PREFIX):] if account.startswith(_SA_PREFIX) else account
            claims.append(Claim("service_account_ref", bare, sa_location(field, i)))
    return claims


def firewall_rule_claims(doc: Any) -> list[Claim]:
    """Claims made by one Compute REST firewall document (``DOCUMENT_EXTRACTORS``)."""
    normalized = normalize_rest(doc)
    if normalized is None:
        logger.debug("firewall document is not a mapping — no claims")
        return []
    claims = _reference_claims(
        normalized,
        network_location="network",
        source_tag_location=lambda i: f"sourceTags[{i}]",
        sa_location=lambda field, i: f"{_REST_SA_FIELDS[field]}[{i}]",
    )
    name = normalized.get("name") or ""
    claims.append(Claim.of("firewall_rule", name, "name", **normalized))
    return claims


def _tf_firewall_claims(address: str, values: Mapping[str, Any]) -> list[Claim]:
    """Claims made by one ``google_compute_firewall`` resource (``TF_EXTRACTORS``)."""
    normalized = normalize_tf(values)
    if normalized is None:
        logger.debug("%s has no mapping values — no firewall claims", address)
        return []
    name = normalized.get("name")
    if isinstance(name, str) and name:
        value = name
    else:
        # An unresolved name: anchor the rule on its terraform address so the
        # claim value and the payload's name agree and stay usable downstream.
        value = address
        normalized = {**normalized, "name": address}
    claims = _reference_claims(
        normalized,
        network_location=f"{address}.network",
        source_tag_location=lambda i: f"{address}.source_tags[{i}]",
        sa_location=lambda field, i: f"{address}.{field}[{i}]",
    )
    claims.append(Claim.of("firewall_rule", value, address, **normalized))
    return claims


# -- document-kind detection --------------------------------------------------


def detect_kind(doc: Any) -> str | None:
    """``"firewall_rule"`` when *doc* is a Compute REST firewall document
    (``kind == "compute#firewall"``), else None."""
    if isinstance(doc, Mapping) and doc.get("kind") == _REST_KIND:
        return "firewall_rule"
    return None


# -- registry wiring ----------------------------------------------------------

#: Document-kind extractors the registry discovers (no edit elsewhere).
DOCUMENT_EXTRACTORS = {"firewall_rule": firewall_rule_claims}

#: Terraform resource extractors the tf hook discovers (no edit elsewhere).
TF_EXTRACTORS = {"google_compute_firewall": _tf_firewall_claims}
