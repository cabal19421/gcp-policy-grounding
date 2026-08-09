"""The seeded mutation contract entries. DATA ONLY -- nothing here executes.

The machinery, the shape gate and the live flip are ``tests/mutation_contract.py``'s;
no register-wide assertion belongs here (that is part 4's, ``-gate``).

SOURCE OF EVERY ``must_fail``, recorded once because it is the same for all:
THIS CHECKOUT'S COLLECT-ONLY PASS -- ``mutation_contract.CHECKOUT_COLLECT``, the
state line's default -- both owner branches being ancestors of HEAD (asserted with
``git merge-base --is-ancestor`` before a single entry was written). Each node
below was then MEASURED, not read: the mutant applied alone to a ``git archive
HEAD`` copy, ``-rA`` reporting the node FAILED, and the unmutated copy green.

``line_hint`` is the design's number from the day of measurement and has DRIFTED;
every anchor is the content slice found in the owner's landed source, widened to
the smallest slice unique inside its ``enclosing`` scope.

MK-I01..MK-I29 and the removal set are NOT here: ESC-GX-SEEDA-001 records the
measured diff-budget overrun that splits them out.
"""

from __future__ import annotations

from tests.mutation_contract import Mutation

_MOD = "gcp_grounding/preflight.py"
_OWNER = "gx-preflight-empty-key"
_T = "tests/test_gcp_preflight.py::"
_G = "tests/test_gcp_policy_gate.py::"

#: A JSON document has no line to point at, so every verdict carries lineno 0.
#: The lineno family below all mutate that 0 and are all widened by one message
#: line, the ``report.add(Verdict(...`` opener repeating inside every scope.
ENTRIES: tuple[Mutation, ...] = (
    Mutation(
        id="MK-P01", module=_MOD, enclosing="ground_policy",
        before='        report.add(Verdict("unverified", "document", source, 0,\n'
               '                           f"{source}: {error} — nothing was checked"))',
        after='        report.add(Verdict("unverified", "document", source, 1,\n'
              '                           f"{source}: {error} — nothing was checked"))',
        line_hint=104,
        behaviour="the unreadable-or-invalid-document abstention points at line 1 "
                  "of a document that has no lines",
        must_fail=(_T + "test_missing_file_fails_open_to_unverified",
                   _T + "test_invalid_json_fails_open_to_unverified"),
        owner=_OWNER),
    Mutation(
        id="MK-P02", module=_MOD, enclosing="ground_policy",
        before='            report.add(Verdict("unverified", "subset", "iam-policy", 0,\n'
               '                               f"{source}: {error} — new⊆old was not decided"))',
        after='            report.add(Verdict("unverified", "subset", "iam-policy", 1,\n'
              '                               f"{source}: {error} — new⊆old was not decided"))',
        line_hint=107,
        behaviour="the new⊆old-not-decided abstention raised beside an unreadable "
                  "document points at a line",
        must_fail=(_T + "test_missing_file_fails_open_to_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P03", module=_MOD, enclosing="ground_policy",
        before='        report.add(Verdict("unverified", "document", source, 0,\n'
               '                           f"{source}: detected {kind} content, but nothing "',
        after='        report.add(Verdict("unverified", "document", source, 1,\n'
              '                           f"{source}: detected {kind} content, but nothing "',
        line_hint=121,
        behaviour="the zero-claims honesty abstention points at a line",
        must_fail=(_T + "test_absent_bindings_key_is_unverified_not_legitimately_empty",),
        owner=_OWNER),
    Mutation(
        id="MK-P04", module=_MOD, enclosing="ground_policy",
        before='if claim.kind == "cel":', after='if claim.kind != "cel":',
        line_hint=130,
        behaviour="every non-CEL claim is sent to the CEL checker and every CEL "
                  "claim skips it. RE-MEASURED IN ISOLATION, which is why it is "
                  "seeded already-killed: applied alone to a git-archive copy it "
                  "reddens 21 nodes across test_gcp_preflight.py and "
                  "test_gcp_policy_gate.py, so its appearance in the live survivor "
                  "list was a sequential-loop artefact and never a coverage gap",
        must_fail=(_G + "test_good_policy_files_pass_with_no_risk",
                   _G + "test_bad_iam_policy_fails_the_gate_with_findings"),
        owner=_OWNER),
    Mutation(
        id="MK-P05", module=_MOD, enclosing="ground_policy",
        before='            report.add(Verdict("unverified", claim.kind, claim.value, 0,',
        after='            report.add(Verdict("unverified", claim.kind, claim.value, 1,',
        line_hint=135,
        behaviour="the no-offline-check-is-wired abstention points at a line",
        must_fail=(_T + "test_claim_kind_no_layer_decides_is_unverified_naming_the_kind",),
        owner=_OWNER),
    Mutation(
        id="MK-P06", module=_MOD, enclosing="_extract_claims",
        before='        report.add(Verdict("unverified", "document", source, 0,\n'
               '                           f"{source}: document kind was not recognized ({shape}) "',
        after='        report.add(Verdict("unverified", "document", source, 1,\n'
              '                           f"{source}: document kind was not recognized ({shape}) "',
        line_hint=192,
        behaviour="the unrecognized-document-kind abstention points at a line",
        must_fail=(_T + "test_unrecognized_document_fails_open_to_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P07", module=_MOD, enclosing="_extract_claims",
        before='            report.add(Verdict("unverified", "document", source, 0,\n'
               '                               f"{source}: detected a terraform plan, but the tf-plan "',
        after='            report.add(Verdict("unverified", "document", source, 1,\n'
              '                               f"{source}: detected a terraform plan, but the tf-plan "',
        line_hint=199,
        behaviour="the plan-detected-but-no-extractor abstention points at a line",
        must_fail=(_T + "test_tf_plan_without_its_extractor_is_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P08", module=_MOD, enclosing="_extract_claims",
        before="                     exc_info=True)", after="                     exc_info=False)",
        line_hint=210,
        behaviour="the claim-extraction-failed debug record loses its traceback. "
                  "The trap: logging stores the literal False, so `exc_info is not "
                  "None` still passes -- only truthiness kills it",
        must_fail=(_T + "test_claim_extraction_failure_logs_its_traceback",),
        owner=_OWNER),
    Mutation(
        id="MK-P09", module=_MOD, enclosing="_extract_claims",
        before='        report.add(Verdict("unverified", "document", source, 0,\n'
               '                           f"{source}: {kind} claim extraction failed ({exc}) "',
        after='        report.add(Verdict("unverified", "document", source, 1,\n'
              '                           f"{source}: {kind} claim extraction failed ({exc}) "',
        line_hint=211,
        behaviour="the claim-extraction-raised abstention points at a line",
        must_fail=(_T + "test_claim_extraction_raising_fails_open_to_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P10", module=_MOD, enclosing="_subset_verdict",
        before='        return [Verdict("unverified", "subset", "iam-policy", 0,\n'
               '                        f"a baseline was given, but the document was detected as "',
        after='        return [Verdict("unverified", "subset", "iam-policy", 1,\n'
              '                        f"a baseline was given, but the document was detected as "',
        line_hint=236,
        behaviour="the baseline-against-a-non-IAM-document abstention points at a line",
        must_fail=(_T + "test_baseline_against_non_iam_document_is_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P11", module=_MOD, enclosing="_subset_verdict",
        before="{kind or 'unrecognized'}", after="{kind and 'unrecognized'}",
        line_hint=238,
        behaviour="the abstention LIES about what was detected: a detected "
                  "org_policy is reported as 'unrecognized' and an undetected "
                  "document renders as 'None'",
        must_fail=(_T + "test_baseline_against_non_iam_document_is_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P12", module=_MOD, enclosing="ground_policy",
        before='            report.add(Verdict("unverified", "subset", "iam-policy", 0,\n'
               '                               f"{baseline_source}: baseline {baseline_error} "',
        after='            report.add(Verdict("unverified", "subset", "iam-policy", 1,\n'
              '                               f"{baseline_source}: baseline {baseline_error} "',
        line_hint=242,
        behaviour="the unreadable-baseline abstention points at a line",
        must_fail=(_T + "test_unreadable_baseline_is_unverified_not_contradicted",),
        owner=_OWNER),
    Mutation(
        id="MK-P13", module=_MOD, enclosing="_subset_verdict",
        before='        return [Verdict("unverified", "subset", "iam-policy", 0,\n'
               '                        f"{baseline_source}: the baseline\'s shape was not "',
        after='        return [Verdict("unverified", "subset", "iam-policy", 1,\n'
              '                        f"{baseline_source}: the baseline\'s shape was not "',
        line_hint=248,
        behaviour="the baseline-is-not-an-IAM-allow-policy abstention points at a line",
        must_fail=(_T + "test_unrecognized_baseline_shape_is_unverified_not_contradicted",),
        owner=_OWNER),
    Mutation(
        id="MK-P14", module=_MOD, enclosing="_subset_verdict",
        before='        return [Verdict("unverified", "subset", "iam-policy", 0,\n'
               '                        f"new⊆old was not decided: {exc}")]',
        after='        return [Verdict("unverified", "subset", "iam-policy", 1,\n'
              '                        f"new⊆old was not decided: {exc}")]',
        line_hint=254,
        behaviour="the subset-check-raised-ValueError abstention points at a line",
        must_fail=(_T + "test_subset_check_raising_value_error_is_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P15", module=_MOD, enclosing="_legitimately_empty",
        before='doc["bindings"] == []', after='doc["bindings"] != []',
        line_hint=155,
        behaviour="an IAM policy that grants nothing stops being legitimately "
                  "empty and one that grants something starts being it -- the "
                  "inversion of the very fix this task landed. Seeded "
                  "already-killed so a later refactor cannot quietly free it",
        must_fail=(_T + "test_legitimately_empty_iam_policy_yields_no_verdicts",),
        owner=_OWNER),
)

#: DELIBERATELY EMPTY, and named rather than omitted: the removal set is split
#: out by ESC-GX-SEEDA-001 along with MK-I01..MK-I29, on the measured budget.
REMOVALS: tuple = ()
