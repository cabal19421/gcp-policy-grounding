"""The APPEND-ONLY escalation register: clauses that cannot be satisfied.

House rule 4 of `designs/gcp-gx-fixes.md` — ESCALATE, DO NOT ROUTE AROUND. If a
clause there cannot be satisfied, append an entry here and land the SPEC-LITERAL
assertion under ``pytest.mark.xfail(strict=True, reason=<the escalation id>)``.
That is a GREEN, NAMED state and the cheapest passing path; rewriting the
assertion to fit the code is a review FAIL.

This file is deliberately NOT frozen — every task may append to it. Its
self-test, ``tests/test_gcp_escalations.py``, IS frozen: it asserts that every
registered node id really carries a STRICT xfail whose reason names its id, that
ids are unique, and that a required-id tuple is still a subset of this register,
so a mandated escalation cannot be quietly deleted.

``strict=True`` is what stops an escalation from being forgotten: the day the
owning task lands the fix, the xfail becomes an XPASS and the suite goes RED,
which forces the entry to be retired deliberately rather than by rot.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Escalation:
    """One clause that could not be satisfied, and where its xfail lives.

    ``id``            stable handle, named in the xfail ``reason``.
    ``clause``        the VERBATIM design text that cannot be satisfied.
    ``unsatisfiable`` one sentence on why.
    ``owner_task``    the task id that raised it.
    ``node_id``       the pytest node carrying the strict-xfailed assertion.
    """

    id: str
    clause: str
    unsatisfiable: str
    owner_task: str
    node_id: str


ESCALATIONS: tuple[Escalation, ...] = (
    Escalation(
        id="ESC-GX-SPEC-001",
        clause="asserts the clause still occurs in some file under `designs/`",
        unsatisfiable=(
            "`designs/` is git-ignored repo-wide and is tracked on no branch, so "
            "it exists only in the main checkout: a clean clone, a CI container "
            "and every git worktree carry NO design corpus at all, and the clause "
            "anchor can only be resolved by following this worktree's `.git` "
            "pointer file back to the main checkout, or skipped loudly when even "
            "that fails. Tracking the corpus, or vendoring the clause text into "
            "the repo, is what would close it."
        ),
        owner_task="gx-spec-register",
        node_id=("tests/test_gcp_spec_assertions.py::"
                 "test_the_design_corpus_is_tracked_in_the_repository"),
    ),
    Escalation(
        id="ESC-GX-SPEC-002",
        clause="every owner must be a task id in this document",
        unsatisfiable=(
            "`SA-SECAST-CALLED-ONCE` pins the strict `calls[\"n\"] == 1` counter "
            "proof in tests/test_gcp_sec_ast.py, which today carries the weakened "
            "`<= 1` that zero calls satisfies; that module is owned by "
            "`sx-sec-ast`, a task of the PREDECESSOR design document, and no task "
            "in gcp-gx-fixes.md owns it — so the entry cannot name an in-document "
            "owner without either dropping the pin or inventing an owner that "
            "will never land. Adding a task to this document that owns "
            "tests/test_gcp_sec_ast.py is what would close it."
        ),
        owner_task="gx-spec-register",
        node_id=("tests/test_gcp_spec_assertions.py::"
                 "test_every_awaiting_owner_is_a_task_in_this_document"),
    ),
    Escalation(
        id="ESC-GX-SEXPR-001",
        clause="the same instance works as a dict key and a set member",
        unsatisfiable=(
            "`CompiledRule` IS frozen and its generated `__hash__` delegates to "
            "its one field, but `sec_artifact.Promise` carries the ast as a "
            "plain `dict`, so hashing an admitted rule raises `TypeError: "
            "unhashable type: 'dict'` on CLEAN, unmutated source — the instance "
            "enters neither a dict nor a set however the dataclass is declared, "
            "and no assertion inside this task's declared path can make it. "
            "Giving `Promise` a hashable ast (a canonical JSON string, or a "
            "frozen mapping) in `gcp_grounding/sec_artifact.py` is what would "
            "close it, and that module is outside the one path this task "
            "declares, `gcp_grounding/sec_rules.py`. MK-S01 itself is NOT parked "
            "and needs no amendment: its killing test still reports FAILED under "
            "the `frozen=False` mutant, on the immutability arm and on the "
            "which-type-refuses arm alike."
        ),
        owner_task="gx-sexpr-one-form",
        node_id=("tests/test_gcp_sec_rules.py::"
                 "test_compiled_rule_instance_is_usable_as_a_dict_key"),
    ),
)


# Escalation owners that are not tasks of designs/gcp-gx-fixes.md. Empty today;
# it exists so a later escalation raised by a predecessor-document task has an
# append-only home and is never forced to edit the frozen self-test.
OUT_OF_DOCUMENT_OWNER_TASKS: frozenset[str] = frozenset()
