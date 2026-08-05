"""The FROZEN spec-assertion register: verbatim predicate text plus the design
clause that mandates it.

WHY THIS FILE EXISTS. RC3 of `designs/gcp-gx-fixes.md` is that agents weaken
spec-named assertions instead of escalating: an equality became ``<=`` on
exactly the failing case, a "called at most once" proof became ``<= 1`` (which
zero calls satisfies), a strict s-expression equality was widened to accept
either of two values. The mechanism against it is to move the frozen artifact
OFF the test module and onto this machine-readable register, so no task is ever
unpassable: a task may always edit its own test module, and may NEVER edit this
register. Weakening a REGISTERED predicate then leaves exactly two options —
edit a frozen acceptance path, which fails review outright, or leave the suite
red. Both are worse than raising a hand.

HOW AN ENTRY IS CHECKED, in ``tests/test_gcp_spec_assertions.py``:

* the named ``module`` is read and the ``predicate`` must occur VERBATIM in it,
  compared after WHITESPACE-ONLY normalization so a re-wrap cannot break it;
* the named ``node_id`` must be collectible;
* the ``clause`` must still occur in some file under ``designs/``, matched by
  TEXT and never by line number, so an unrelated edit to the design cannot rot
  this check;
* ids are unique, and every module missing from the checkout must be listed in
  ``PENDING_MODULES``, so deleting any OTHER module is caught immediately.

THE TWO RULES THAT KEEP THE REGISTER PASSABLE ON THE DAY IT LANDS. Most
predicates here belong to LATER tasks, and each of the five strict reversals
names a node that TODAY carries the weakened form. Neither may be resolved by
softening the seeded text or by dropping the entry.

(a) An entry whose NODE ID is not collectible is automatically PENDING and only
    its shape is checked, so a task that has not landed yet cannot redden this
    suite.
(b) An entry whose node IS collectible while its predicate is ABSENT fails,
    UNLESS its id appears in ``AWAITING`` naming the OWNER TASK for it. Every
    owner must be a task id in ``TASK_IDS``, the entry count is pinned in the
    self-test and may only SHRINK, and PRESENCE ALWAYS WINS: the check looks for
    the predicate FIRST, so when the owning task lands the strict text the entry
    passes with NO edit to this register. That is what lets the register be
    frozen for everyone — nobody ever needs to write to it.

RESIDUAL RISK, the node-id mismatch: an owning task that lands its assertion
under a DIFFERENT node id leaves its entry PENDING rather than red — the entry
goes quiet instead of biting. That is why the owning task's body in the design
carries the same predicate verbatim, and the review gate, not this suite, is
what catches the mismatch.

RESIDUAL RISK, stated plainly: a module still listed in ``PENDING_MODULES`` can
later be DELETED without this check firing, because a missing module is exactly
the pending shape. What closes that is the in-repo mutation contract — its
per-family coverage assertion and its collect-only node-id check, which require
the named nodes to EXIST and to go red when their subject is removed. This
register pins TEXT; the contract pins BEHAVIOUR; neither substitutes for the
other.

DEVIATION, recorded rather than hidden: the design says the self-test reads the
named module with ``inspect.getsource``. It does — but on a module object built
with ``importlib.util.module_from_spec`` and never EXECUTED, so reading a module
from another family cannot run that family's collection-time probes and cannot
fail on an import that is only satisfiable in a merged checkout. The bytes read
are the same bytes.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SpecAssertion:
    """One pinned predicate and the design clause that mandates it.

    ``id``        stable handle, referenced by ``AWAITING`` and by review.
    ``module``    repo-relative file whose source must carry ``predicate``.
    ``node_id``   pytest node id that demonstrates it; when the module is a
                  product module this names the test that exercises it.
    ``predicate`` the VERBATIM source text that must still be present.
    ``clause``    a verbatim substring of the design text that mandates it.
    """

    id: str
    module: str
    node_id: str
    predicate: str
    clause: str


# The verdict-lineno invariant, seeded three times. The design's amendment
# mandates two entries (preflight, sec_rules); the `gx-evidence-invokers` body
# ALSO marks the same predicate REGISTERED in tests/test_gcp_evidence_floor.py,
# and "seed every assertion this design doc marks REGISTERED" governs, so the
# third is seeded too. More coverage of a frozen invariant is never a weakening.
_LINENO = "all(v.lineno == 0 for v in"
_LINENO_CLAUSE = (
    "policy documents have no line numbers, so every verdict's lineno is 0 "
    "and the json-path location leads the message instead"
)


ASSERTIONS: tuple[SpecAssertion, ...] = (
    # -- Gate 0: landed before this task, so both of these must be PRESENT ----
    SpecAssertion(
        id="SA-PREFLIGHT-BINDINGS-PRESENT",
        module="gcp_grounding/preflight.py",
        node_id=("tests/test_gcp_preflight.py::"
                 "test_absent_bindings_key_is_unverified_not_legitimately_empty"),
        predicate='"bindings" in doc and doc["bindings"] == []',
        clause="THE FIX is one line: require the key to be present",
    ),
    SpecAssertion(
        id="SA-PREFLIGHT-NO-LINENO",
        module="tests/test_gcp_preflight.py",
        node_id="tests/test_gcp_preflight.py::test_invalid_json_fails_open_to_unverified",
        predicate=_LINENO,
        clause=_LINENO_CLAUSE,
    ),
    # -- Gate 1a: the evidence floor -----------------------------------------
    SpecAssertion(
        id="SA-INVOKERS-ROWS-EXAMINED",
        module="gcp_grounding/registry.py",
        node_id=("tests/test_gcp_evidence_floor.py::"
                 "test_a_decision_over_an_empty_collection_is_downgraded"),
        predicate="rows_examined == 0",
        clause=("replace it with an `unverified` of the SAME kind and target whose "
                "message names the empty collections and the status it replaced"),
    ),
    SpecAssertion(
        id="SA-SECRULES-NO-LINENO",
        module="tests/test_gcp_sec_rules.py",
        node_id=("tests/test_gcp_sec_rules.py::"
                 "test_the_z3_absent_abstention_is_identified_and_carries_no_line_number"),
        predicate=_LINENO,
        clause=_LINENO_CLAUSE,
    ),
    SpecAssertion(
        id="SA-EVIDENCE-FLOOR-NO-LINENO",
        module="tests/test_gcp_evidence_floor.py",
        node_id=("tests/test_gcp_evidence_floor.py::"
                 "test_the_floors_own_abstentions_are_identified_and_carry_no_line_number"),
        predicate=_LINENO,
        clause=_LINENO_CLAUSE,
    ),
    # -- Gate 1b: the assertion helpers --------------------------------------
    SpecAssertion(
        id="SA-CHANNELS-INCIDENTAL-KINDS",
        module="tests/agentic/asserts.py",
        node_id=("tests/test_gcp_assert_channels.py::"
                 "test_the_incidental_kinds_are_the_two_the_design_names"),
        predicate='INCIDENTAL_KINDS = frozenset({"resource_type", "resource_type_ref"})',
        clause="an incidental vocabulary hit is not in the candidate set at all",
    ),
    SpecAssertion(
        id="SA-CHANNELS-ABSTAIN-SOURCE",
        module="tests/agentic/asserts.py",
        node_id=("tests/test_gcp_assert_channels.py::"
                 "test_an_abstain_about_another_file_is_not_this_files_abstain"),
        predicate='report["source"] ==',
        clause=("""require `report["source"]` to equal the event's """
                "`tool_input.file_path` whenever `outcome.event` is not None"),
    ),
    SpecAssertion(
        id="SA-CHANNELS-BLOCK-SUBSTRINGS",
        module="tests/agentic/asserts.py",
        node_id="tests/test_gcp_assert_channels.py::test_exit_two_alone_is_not_a_block",
        predicate="assert substrings,",
        clause="a block that tells the agent nothing is not a block",
    ),
    # The first of the five observed weakenings, seeded in its STRICT form.
    SpecAssertion(
        id="SA-CHANNELS-RECORDED-ONE-MATCH",
        module="tests/agentic/asserts.py",
        node_id=("tests/test_gcp_agentic_iam.py::"
                 "test_every_adversarial_case_has_a_recorded_verdict_assertion"),
        predicate="len(matches) == 1",
        clause="asserting exactly one match",
    ),
    SpecAssertion(
        id="SA-CHANNELS-PASSED-BYTE-EMPTY",
        module="tests/agentic/asserts.py",
        node_id="tests/test_gcp_hookrunner.py::test_clean_policy_passes_byte_silently",
        predicate='outcome.stdout == "" and outcome.stderr == ""',
        clause="both are REGISTERED and neither may move",
    ),
    SpecAssertion(
        id="SA-BUDGET-CHECKED-IN-CONFTEST",
        module="tests/conftest.py",
        node_id=("tests/test_gcp_hookrunner.py::"
                 "test_a_module_that_imports_only_run_hook_cannot_opt_out_of_the_budget"),
        predicate="budget.check()",
        clause=("Move the binding into tests/conftest.py as a SESSION-SCOPED "
                "AUTOUSE fixture so no module can opt out"),
    ),
    # -- the remaining observed weakenings, in their STRICT form -------------
    SpecAssertion(
        id="SA-BENIGN-EXIT-CODE-SET",
        module="tests/test_gcp_agentic_benign.py",
        node_id="tests/test_gcp_agentic_benign.py::test_every_exit_code_is_exactly_zero",
        predicate="codes == {0}",
        clause="the benign session's exit-code SET EQUALITY, `codes == {0}`",
    ),
    SpecAssertion(
        id="SA-BENIGN-STDERR-BYTE-EMPTY",
        module="tests/test_gcp_agentic_benign.py",
        node_id=("tests/test_gcp_agentic_benign.py::"
                 "test_the_whole_benign_session_emits_no_stderr_at_all"),
        predicate='combined == ""',
        clause='and its byte-empty aggregate stderr, `combined == ""`',
    ),
    SpecAssertion(
        id="SA-SECAST-CALLED-ONCE",
        module="tests/test_gcp_sec_ast.py",
        node_id="tests/test_gcp_sec_ast.py::test_ensure_domains_called_at_most_once",
        predicate='calls["n"] == 1',
        clause="being called at most once",
    ),
    SpecAssertion(
        id="SA-SEXPR-ONE-FORM",
        module="gcp_grounding/sec_rules.py",
        node_id="tests/test_gcp_sec_rules.py::test_weakened_ast_is_refused_by_sexpr_mismatch",
        predicate="promise.sexpr !=",
        clause="REFUSE TO REGISTER",
    ),
    SpecAssertion(
        id="SA-REGISTRY-BYTE-IDENTITY",
        module="tests/test_gcp_registry.py",
        node_id="tests/test_gcp_registry.py::test_no_providers_is_byte_identical",
        predicate="got == sorted(expected)",
        clause="the registry byte-identity equality, `got == sorted(expected)`",
    ),
    # The inverted spelling the review found ("... not in ...") cannot match
    # this substring, which is the point of pinning the POSITIVE form.
    SpecAssertion(
        id="SA-IAM-UNTRANSLATABLE-NAMED",
        module="tests/test_gcp_agentic_iam.py",
        node_id=("tests/test_gcp_agentic_iam.py::"
                 "test_adversarial_proposal_is_blocked_or_recorded"),
        predicate='UNTRANSLATABLE_EXPRESSION in verdict["message"]',
        clause=("the clause requires exactly one abstention whose MESSAGE NAMES "
                "THE OFFENDING EXPRESSION verbatim"),
    ),
)


# Entry id -> the task that OWES the strict predicate. An entry listed here is
# green while its owner has not landed; PRESENCE ALWAYS WINS, so the day the
# owner lands the strict text nothing here needs editing. This tuple may only
# SHRINK — its ceiling is pinned in tests/test_gcp_spec_assertions.py.
#
# SA-PREFLIGHT-BINDINGS-PRESENT and SA-PREFLIGHT-NO-LINENO are deliberately
# ABSENT from this tuple: `gx-preflight-empty-key` landed before this task, so
# both must be PRESENT today and this suite goes red if either is weakened.
AWAITING: tuple[tuple[str, str], ...] = (
    ("SA-INVOKERS-ROWS-EXAMINED", "gx-evidence-invokers"),
    ("SA-SECRULES-NO-LINENO", "gx-evidence-invokers"),
    ("SA-EVIDENCE-FLOOR-NO-LINENO", "gx-evidence-invokers"),
    ("SA-REGISTRY-BYTE-IDENTITY", "gx-evidence-invokers"),
    ("SA-CHANNELS-INCIDENTAL-KINDS", "gx-assert-channels"),
    ("SA-CHANNELS-ABSTAIN-SOURCE", "gx-assert-channels"),
    ("SA-CHANNELS-BLOCK-SUBSTRINGS", "gx-assert-channels"),
    ("SA-CHANNELS-RECORDED-ONE-MATCH", "gx-assert-channels"),
    ("SA-CHANNELS-PASSED-BYTE-EMPTY", "gx-assert-channels"),
    ("SA-BUDGET-CHECKED-IN-CONFTEST", "gx-hookrunner-budget"),
    ("SA-BENIGN-EXIT-CODE-SET", "gx-agentic-benign-repin"),
    ("SA-BENIGN-STDERR-BYTE-EMPTY", "gx-agentic-benign-repin"),
    ("SA-SECAST-CALLED-ONCE", "sx-sec-ast"),
    ("SA-SEXPR-ONE-FORM", "gx-sexpr-one-form"),
    ("SA-IAM-UNTRANSLATABLE-NAMED", "gx-agentic-iam-repin"),
)


# An AWAITING owner that is NOT a task in gcp-gx-fixes.md, mapped to the
# escalation that records why. The design requires every owner to be a task id
# in that document; `tests/test_gcp_sec_ast.py` is owned by `sx-sec-ast`, a task
# of the PREDECESSOR design document, and no task in this one can own it. That
# clause is therefore escalated rather than routed around: the spec-literal
# assertion is landed under xfail(strict=True), and this mapping keeps the
# live, non-literal check strict enough to still catch a typo'd owner.
OUT_OF_DOCUMENT_OWNERS: dict[str, str] = {
    "sx-sec-ast": "ESC-GX-SPEC-002",
}


# Modules a registered entry names that are NOT in this checkout yet. A missing
# module makes its entries PENDING; a missing module NOT listed here is a
# deletion and fails immediately. See the docstring's second residual risk for
# what this cannot catch.
PENDING_MODULES: frozenset[str] = frozenset({
    "gcp_grounding/registry.py",
    "gcp_grounding/sec_rules.py",
    "tests/agentic/asserts.py",
    "tests/conftest.py",
    "tests/test_gcp_agentic_benign.py",
    "tests/test_gcp_agentic_iam.py",
    "tests/test_gcp_evidence_floor.py",
    "tests/test_gcp_registry.py",
    "tests/test_gcp_sec_ast.py",
    "tests/test_gcp_sec_rules.py",
})


# Every `(id: ...)` in designs/gcp-gx-fixes.md, in document order. The self-test
# asserts this is a SUBSET of the ids the design really declares whenever the
# corpus can be resolved — a subset, not an equality, so a later amendment that
# ADDS a task cannot redden this frozen file.
#
# OPERATOR INTEGRATION CORRECTION. A subset assertion survives an amendment that
# ADDS a task; it does NOT survive one that SPLITS a task, because the id this
# file names then stops being declared at all. AMENDMENT 4 split
# `gx-mutation-contract` into the four parts below, so the single id was a task
# the design does not declare and
# `test_task_ids_are_a_subset_of_the_documents_own_task_ids` was red on the
# owning branch too. The four successors replace it: nothing else in the tree
# referenced the retired id, no escalation or AWAITING entry owns it, the design
# declares all four verbatim, and the subset assertion itself is untouched.
TASK_IDS: frozenset[str] = frozenset({
    "gx-preflight-empty-key",
    "gx-evidence-module",
    "gx-evidence-invokers",
    "gx-evidence-lint",
    "gx-assert-channels",
    "gx-capability-probes",
    "gx-hookrunner-budget",
    "gx-mutation-contract-machinery",
    "gx-mutation-contract-seed-a",
    "gx-mutation-contract-seed-b",
    "gx-mutation-contract-gate",
    "gx-spec-register",
    "gx-sexpr-one-form",
    "gx-secdomains-record-shape",
    "gx-secdomains-tf-envelope",
    "gx-hierfw-records",
    "gx-hierfw-placement",
    "gx-iam-escalation-evidence",
    "gx-org-claim-completeness",
    "gx-org-prior-content",
    "gx-org-baseline-node",
    "gx-vpcsc-record-guards",
    "gx-vpcsc-enforcement-surface",
    "gx-vpcsc-solver-sources",
    "gx-sec-cli-zero-rules",
    "gx-sec-cli-hook-failopen",
    "gx-agentic-iam-repin",
    "gx-agentic-network-repin",
    "gx-agentic-vpcsc-repin",
    "gx-agentic-abstain-repin",
    "gx-agentic-secreq-repin",
    "gx-agentic-benign-repin",
})
