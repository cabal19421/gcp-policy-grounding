"""Sites the evidence lint may not yet fail on — one explicit tuple, no globs.

Every entry is a module path, a LINE-ANCHORED source segment, and one sentence
saying why the site is out of channel today. The count is pinned in
``tests/test_gcp_evidence_lint.py`` and may only SHRINK: the lint asserts both
``len(ALLOWLIST) <= PINNED_MAX`` *and* that every entry still matches a site the
lint actually reports, so an entry whose site was repaired (or whose line moved)
is a FAILURE, not a permanent hole. Deleting the entry is the fix.

Seed this only with a site whose repair belongs to another task. Prefer empty.
"""

from __future__ import annotations

from typing import NamedTuple


class Allowed(NamedTuple):
    """One sanctioned exception, anchored tightly enough that it cannot rot."""

    module: str
    line: int
    segment: str
    justification: str

    @property
    def site(self) -> tuple[str, int, str]:
        """The identity the lint matches an entry against."""
        return (self.module, self.line, self.segment)


#: The inventory measured against the tree at the moment the lint landed — the
#: evidence that the lint has teeth. Each repair belongs to the domain task that
#: owns the file, all of which land after this one; the lint exists so that
#: those repairs are the only way out of this tuple.
ALLOWLIST: tuple[Allowed, ...] = (
    Allowed(
        "gcp_grounding/fw_claims.py", 286, 'normalized.get("source_tags", ())',
        "The normalized rule mapping is built by fw_claims' own two normalizers "
        "rather than read from a document, so re-spelling this read is the "
        "fw-claims task's call about its internal normalizer contract.",
    ),
    Allowed(
        "gcp_grounding/fw_claims.py", 290, 'normalized.get(field, ())',
        "Same internal normalizer contract as the source_tags read above, over "
        "the two service-account fields.",
    ),
    Allowed(
        "gcp_grounding/fw_claims.py", 310, 'normalized.get("name") or ""',
        "The empty-string fallback is load-bearing for the claim location that "
        "an unnamed rule gets, so replacing it changes emitted claims and "
        "belongs to the fw-claims task that owns those byte-pinned payloads.",
    ),
    Allowed(
        "gcp_grounding/sec_domains.py", 357, "_iterable(values)",
        "_iterable launders every dimension builder's input in sec_domains, and "
        "routing them through evidence.rows means opening a ledger inside the "
        "collection extractors, which is the sec-domains task's change.",
    ),
    Allowed(
        "gcp_grounding/sec_domains.py", 375, "_iterable(values)",
        "Same _iterable laundering, in the string-dimension builder.",
    ),
    Allowed(
        "gcp_grounding/sec_domains.py", 381, "_iterable(entries)",
        "Same _iterable laundering, in the layer-4 dimension builder.",
    ),
    Allowed(
        "gcp_grounding/sec_domains.py", 435, "_iterable(ports)",
        "Same _iterable laundering, in the port-value builder.",
    ),
    Allowed(
        "gcp_grounding/tf_claims.py", 136,
        '_module_resources(planned.get("root_module"))',
        "A plan whose root_module is unreadable yields no resources and so no "
        "claims, which the tf-claims task must turn into an abstention rather "
        "than a clean plan.",
    ),
    Allowed(
        "gcp_grounding/tf_claims.py", 165, "_module_resources(child)",
        "The recursive descent inside _module_resources itself, repaired by the "
        "same tf-claims change as its call site above.",
    ),
)
