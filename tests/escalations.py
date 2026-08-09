"""The APPEND-ONLY escalation register: clauses that cannot be satisfied.

House rule 4 — ESCALATE, DO NOT ROUTE AROUND. When a clause of
`designs/gcp-gx-fixes.md` cannot be satisfied where it was asked for, the
cheapest honest path is to say so by name: an entry here, and the spec-literal
assertion landed under ``pytest.mark.xfail(strict=True, reason=<the escalation
id>)``. That is a GREEN, NAMED state. Rewriting the assertion to fit the code
instead is a review FAIL.

Entries are APPEND-ONLY: an id, once published, is quoted from ``xfail``
reasons and from module docstrings, so removing or renaming one silently
detaches those references. An escalation is CLOSED by landing its fix and
deleting the ``xfail`` — the entry stays, with ``closed_by`` naming the change.

``strict=True`` is what stops an escalation from being forgotten: the day the
owning task lands the fix, the xfail becomes an XPASS and the suite goes RED,
which forces the entry to be retired deliberately rather than by rot.

This file is deliberately NOT frozen — every task may append to it. Its
self-test, ``tests/test_gcp_escalations.py``, IS frozen: it asserts that every
:data:`ESCALATIONS` node id really carries a STRICT xfail whose reason names its
id, that ids are unique, and that a required-id tuple is still a subset of this
register, so a mandated escalation cannot be quietly deleted.

TWO REGISTERS, ONE FILE. :data:`ESCALATIONS` is the xfail-governed register:
every entry names the pytest node whose strict xfail carries it, which is what
the frozen self-test walks. :data:`PRODUCT_ESCALATIONS` is for an escalation
whose subject is PRODUCT code that a test task may not edit — vendored
``gcp_grounding/core/`` above all — where there is no assertion to xfail
because the honest test already passes and it is the product that is wrong.
Such an entry carries ``product_fix`` and ``residual_risk`` instead of a
``node_id``, and is quoted from the module that works around it. Both tuples
are append-only; neither entry may be moved to the other register to make a
schema fit.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Escalation:
    """One clause that could not be satisfied, and where its xfail lives.

    ``id``            stable handle, named in the xfail ``reason``. Never
                      reused, never renamed.
    ``clause``        the VERBATIM design text that cannot be satisfied.
    ``unsatisfiable`` why it cannot be satisfied here — the measured fact, not
                      an opinion.
    ``owner_task``    the task id that raised it.
    ``node_id``       the pytest node carrying the strict-xfailed assertion.
    """

    id: str
    clause: str
    unsatisfiable: str
    owner_task: str
    node_id: str


@dataclass(frozen=True)
class ProductEscalation:
    """One clause blocked by PRODUCT code a test task may not edit.

    There is no assertion to xfail: the honest test passes, and it is the
    product that is wrong, so the entry records the fix and what is exposed
    until it lands rather than a node id.
    """

    #: Stable id, quoted from the module that works around it.
    id: str
    #: The clause, in the design's own words.
    clause: str
    #: What stops it being satisfied here — the measured fact, not an opinion.
    why: str
    #: The change that would close it, concretely enough to be actioned.
    product_fix: str
    #: What is exposed while it is open. An escalation is not a dismissal.
    residual_risk: str
    #: The commit or task that landed ``product_fix``; empty while open.
    closed_by: str = ""


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
    Escalation(
        id="ESC-GX-SECCLI-001",
        clause=("the recorded source paths are then cwd-relative and the check "
                "mode reports spurious drift"),
        unsatisfiable=(
            "`sec_compile._repo_relative` anchors a recorded source path against "
            "the nearest `pyproject.toml`, and with no such ancestor falls back "
            "to `os.path.relpath(document, os.getcwd())` — so the artifact's "
            "bytes depend on the working directory the compile ran from, and a "
            "`--check` run from a different one re-renders a different "
            "`source.file` and reports drift on a corpus nobody touched. The "
            "clause names this as the SYMPTOM of unanchored paths and the task "
            "body declares root-cause path anchoring out of scope per the "
            "Non-goals, carrying only the partial mitigation: the compile now "
            "REFUSES SILENCE about it, emitting an `unverified` sec:compile "
            "verdict that names the directory and this id. Anchoring the "
            "recorded path to the corpus directory itself — or storing it "
            "absolute — in `gcp_grounding/sec_compile.py` is what would close "
            "it, and that module is outside this task's declared path, "
            "`gcp_grounding/cli.py`."
        ),
        owner_task="gx-sec-cli-zero-rules",
        node_id=("tests/test_gcp_sec_cli.py::"
                 "test_check_outside_the_repo_does_not_report_spurious_drift"),
    ),
    Escalation(
        id="ESC-GX-TFPROMISE-001",
        clause="the abstention is only correct if the positive case still works",
        unsatisfiable=(
            "THE POSITIVE HALF OF THE PAIR CANNOT BE DEMONSTRATED IN THE MERGED "
            "TREE, and no assertion inside the module that pins it can make it. "
            "`test_the_promise_abstains_over_terraform_and_is_live_over_the_estate` "
            "is written as a PAIR: arm one abstains over a terraform-only view, "
            "arm two adds the merged agentic estate snapshot, DECLARES the "
            "category complete, and the `sec:vpc_firewall` promise then decides — "
            "`contradicted` — which is what stops the abstention being an absent "
            "rule wearing a cautious face. MEASURED in the integrated tree, arm "
            "two's promise is `unverified` as well: `provenance` caps any category "
            "a TERRAFORM source contributed to at 'partial', arm two configures "
            "the terraform state beside the estate snapshot, and the "
            "universal-negative gate refuses to discharge a promise that reasons "
            "from absence over a partial view. `--completeness complete` does not "
            "lift that cap and must not — the alternative is an estate-wide clean "
            "bill of health from a view that sees only part of the estate. Nor can "
            "a witness supply the contradiction: the estate this suite commits "
            "holds no open-SSH rule, and the widened rule lives in the PROPOSAL, "
            "i.e. the `proposed_firewall_rules` collection this promise "
            "deliberately does not quantify over. So the promise abstains in BOTH "
            "arms. What would CLOSE this sits outside any test module: an estate "
            "source whose contribution is not capped at 'partial' by a terraform "
            "sibling, or a committed estate fixture carrying the open-SSH witness "
            "the promise quantifies over — the provenance and estate-fixture "
            "owners' decisions, not a test's. Until then the pair's positive half "
            "is carried on a DIFFERENT channel and asserted there rather than "
            "assumed: the estate-tier `firewall_reopen` check contradicts the "
            "widening over the estate and decides nothing over the terraform-only "
            "view, which the live test now pins on both arms."
        ),
        owner_task="tx-agentic-tf-benign",
        node_id=("tests/test_gcp_agentic_tf_benign.py::"
                 "test_the_promise_contradicts_the_widening_over_the_estate"),
    ),
    Escalation(
        id="ESC-GX-SEEDA-001",
        clause="if it will not fit, escalate for a further split rather than ship it",
        unsatisfiable=(
            "MEASURED, not projected, and measured BEFORE the rest was written as "
            "the body directs. Five entries of the mandated ten-field shape were "
            "written in final form and measured as diff lines: MK-P01 778, MK-P02 "
            "729, MK-P03 662, MK-I01 531, MK-I02 542 — mean 648, inside the body's "
            "own 450-700 estimate. So 44 entries alone are ~28,500 characters, the "
            "file header measured 743, and the removal set sits on top: ~34,000 "
            "against a binding 18,000. THE TWO HALVES THE BODY ASKS FOR DO NOT BOTH "
            "FIT EITHER: MK-I01..MK-I29 alone measure ~17,700 before a header, and "
            "the removal set cannot join either half. THE SPLIT THAT DOES FIT IS "
            "THREE WAYS, on MK id ranges: (a) MK-P01..MK-P15, measured 11,686 "
            "including the header, WHICH THIS DIFF SHIPS; (b) MK-I01..MK-I15, "
            "~9,200; (c) MK-I16..MK-I29 plus the removal set, ~14,200. Slicing to "
            "the measured diff and handing the remainder on is this chain's own "
            "established answer — the five machinery slices each did exactly that "
            "— and every guard is intact: nothing is thinned, no must_fail or "
            "behaviour trimmed, no annotation lowered, no exclusion added, no "
            "third state invented, and the 15 shipped entries are all ACTIVE and "
            "all MEASURED killing (mutant applied alone to a git archive HEAD "
            "copy, -rA reporting FAILED, the unmutated copy green). ONE FURTHER "
            "FINDING FOR WHOEVER SEEDS THE REMOVALS: the body mandates a `pending` "
            "mark, an `owner` and an EXPLICIT field naming which of the two "
            "spellings each removal uses, and the frozen `Removal` dataclass "
            "carries none of those three — it is id, subject, family, apply, "
            "must_fail — so that part must either subclass it in this data module "
            "or the frozen type must gain the fields, which is a decision for the "
            "gate's owner and not something to settle by dropping a mandated "
            "field. Landing parts (b) and (c) is what closes this."
        ),
        owner_task="gx-mutation-contract-seed-a",
        node_id=("tests/test_gcp_mutation_entries.py::"
                 "test_the_seed_covers_every_amendment_2_entry_and_the_removal_set"),
    ),
)


PRODUCT_ESCALATIONS: tuple[ProductEscalation, ...] = (
    ProductEscalation(
        id="ESC-HOOKRUNNER-NO-Z3-BANNER",
        clause=(
            "assert_passed's byte-empty-both-streams contract must hold in the "
            "no-z3 world the harness explicitly supports, without relaxing "
            "assert_passed."
        ),
        why=(
            "A clean hook run on a clean policy writes 236 bytes to stderr in "
            "that world: core/solver.py:116-120 logs 'z3 package found but "
            "failed to initialize (...) — falling back to the builtin solver' "
            "at WARNING, and with no setup_logging() call logging's lastResort "
            "handler puts the bare message on stderr. The harness side is "
            "fixed — tests.agentic.hookrunner.STDERR_ALLOWLIST filters that "
            "exact line out of HookOutcome.stderr and keeps it on stderr_raw — "
            "but that changes THE MEASURING INSTRUMENT, NOT THE PRODUCT. "
            "gcp_grounding/core/ is vendored and MUST NOT be edited, so the "
            "product half cannot be fixed from a test task at all."
        ),
        product_fix=(
            "Demote the fallback warning to debug on the hook path, in the "
            "module that owns the solver: core/solver.py's get_solver() should "
            "log the 'found but failed to initialize' fallback at DEBUG (the "
            "backend is already reported by --explain and by the report "
            "document's `backend` field), or gcp_grounding should own the "
            "solver selection in a non-vendored wrapper that logs at DEBUG "
            "when running as a PostToolUse hook."
        ),
        residual_risk=(
            "On a machine whose solver is installed but not initialisable — a "
            "mismatched libz3, a wrong-arch wheel — the gate writes that line "
            "to the hook's stderr ONCE PER TOOL CALL. The hook's stderr is a "
            "contract surface: Claude Code feeds it back to the agent, and the "
            "operator reads it. A guardrail that chatters on every clean edit "
            "is a guardrail that gets switched off. Nothing downstream may "
            "claim unconditional byte-silence without naming the filtered line "
            "and why it is filtered."
        ),
    ),
)


# Escalation owners that are not tasks of designs/gcp-gx-fixes.md. It exists so
# an escalation raised against a PREDECESSOR document's task has an append-only
# home and is never forced to edit the frozen self-test.
#
# `tx-agentic-tf-benign` is declared in designs/gcp-tf-source.md, the predecessor
# document that owns tests/test_gcp_agentic_tf_benign.py; ESC-GX-TFPROMISE-001 is
# raised against its promise pair and no task of gcp-gx-fixes.md owns that module.
OUT_OF_DOCUMENT_OWNER_TASKS: frozenset[str] = frozenset({
    "tx-agentic-tf-benign",
})
