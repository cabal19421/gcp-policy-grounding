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

MK-I16..MK-I29 and the removal set are NOT here: ESC-GX-SEEDA-001 records the
measured diff-budget overrun that splits them out. MK-I01..MK-I15 -- piece (b)
of that measured three-way split -- are appended below under those same rules,
their anchors read from ``agent/gx-evidence-invokers``' landed source and their
nodes measured the same way, one mutant at a time in its own archive copy.
"""

from __future__ import annotations

from tests.mutation_contract import Mutation

_MOD = "gcp_grounding/preflight.py"
_OWNER = "gx-preflight-empty-key"
_T = "tests/test_gcp_preflight.py::"
_G = "tests/test_gcp_policy_gate.py::"

_IR, _ID = "gcp_grounding/registry.py", "gcp_grounding/sec_domains.py"
_IS, _IOWNER = "gcp_grounding/sec_rules.py", "gx-evidence-invokers"
_TR = "tests/test_gcp_registry.py::"
_TD = "tests/test_gcp_sec_domains.py::"
_TS = "tests/test_gcp_sec_rules.py::"
#: The protocol table is module-level, so its anchor is the one-line snippet of
#: its own statement -- which occurs exactly once -- and not a def name.
_TABLE = "PROTOCOL_NUMBERS: dict[str, int] = {"

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
    # -- ESC-GX-SEEDA-001 piece (b): the evidence funnel's first fifteen. ----
    Mutation(
        id="MK-I01", module=_IR, enclosing="CheckContext",
        before="frozen=True", after="frozen=False", line_hint=77,
        behaviour="CheckContext stops being frozen, so a check can mutate the "
                  "context it is handed and the record is no longer hashable",
        must_fail=(_TR + "test_check_context_is_frozen_and_hashable_by_intent",),
        owner=_IOWNER),
    Mutation(
        id="MK-I02", module=_ID, enclosing=_TABLE,
        before='"icmp": 1', after='"icmp": 2', line_hint=171,
        behaviour="the IANA table calls icmp 2, which is igmp, so an icmp rule "
                  "encodes the wrong number and matches the wrong promise",
        must_fail=(_TD + "test_a_protocol_name_encodes_its_own_iana_number[icmp-1-2]",),
        owner=_IOWNER),
    Mutation(
        id="MK-I03", module=_ID, enclosing=_TABLE,
        before='"udp": 17', after='"udp": 18', line_hint=171,
        behaviour="the table calls udp 18, silently changing which promise "
                  "matches a udp firewall rule, with no verdict text to say so",
        must_fail=(_TD + "test_a_protocol_name_encodes_its_own_iana_number[udp-17-18]",),
        owner=_IOWNER),
    Mutation(
        id="MK-I04", module=_ID, enclosing=_TABLE,
        before='"ipv6-icmp": 58', after='"ipv6-icmp": 59', line_hint=172,
        behaviour="the table calls ipv6-icmp 59, silently changing which promise "
                  "matches an ipv6-icmp rule",
        must_fail=(_TD + "test_a_protocol_name_encodes_its_own_iana_number"
                         "[ipv6-icmp-58-59]",),
        owner=_IOWNER),
    Mutation(
        id="MK-I05", module=_ID, enclosing="_sorted",
        before="(0, str(record[field]))", after="(1, str(record[field]))",
        line_hint=225,
        behaviour="the sort key collapses the two ranks, so an absent key sorts "
                  "BEFORE every present one and the records a witness is drawn "
                  "from are silently reordered",
        must_fail=(_TD + "test_a_row_missing_a_field_sorts_after_every_row_that_"
                         "carries_it",),
        owner=_IOWNER),
    Mutation(
        id="MK-I06", module=_ID, enclosing="_str_dimension",
        before="isinstance(v, str) and v", after="isinstance(v, str) or v",
        line_hint=254,
        behaviour="empty strings AND non-string truthy values enter a string "
                  "dimension, whose empty string is reserved for an honest "
                  "captured-empty scalar",
        must_fail=(_TD + "test_a_string_dimension_takes_real_strings_and_nothing_else",),
        owner=_IOWNER),
    Mutation(
        id="MK-I07", module=_ID, enclosing="_protocol_number",
        before='protocol is None or protocol == "all"',
        after='protocol is None and protocol == "all"', line_hint=290,
        behaviour="both the absent protocol and the literal \"all\" fall through "
                  "to the undecidable, so EVERY all-protocols rule abstains "
                  "instead of omitting the protocol key",
        must_fail=(_TD + "test_an_all_protocols_rule_omits_the_protocol_key_and_"
                         "still_evaluates",),
        owner=_IOWNER),
    Mutation(
        id="MK-I08", module=_ID, enclosing="_protocol_number",
        before="not 0 <= number <= 255", after="not 1 <= number <= 255",
        line_hint=302,
        behaviour="protocol 0, HOPOPT, is refused as though it had no IANA "
                  "number, so a legal value makes the whole rule abstain",
        must_fail=(_TD + "test_protocol_zero_is_hopopt_and_is_a_legal_value",),
        owner=_IOWNER),
    Mutation(
        id="MK-I09", module=_ID, enclosing="_port_values",
        before="high - low + 1 > MAX_PORT_SPAN",
        after="high - low + 1 >= MAX_PORT_SPAN", line_hint=321,
        behaviour="a range of exactly MAX_PORT_SPAN ports is treated as wide and "
                  "stops being enumerated -- a real boundary, off by one port",
        must_fail=(_TD + "test_a_range_of_exactly_the_maximum_span_is_still_enumerated",),
        owner=_IOWNER),
    Mutation(
        id="MK-I10", module=_ID, enclosing="_port_values",
        before="wide = True", after="wide = False", line_hint=324,
        behaviour="the wide flag is never set, so the port-key-omitted row is "
                  "never appended and a port-mentioning promise UNDER-MATCHES a "
                  "wide range instead of abstaining loudly -- RC1 in the port axis",
        must_fail=(_TD + "test_a_wide_port_range_omits_the_port_key_so_a_port_"
                         "promise_abstains",),
        owner=_IOWNER),
    Mutation(
        id="MK-I11", module=_ID, enclosing="_port_bounds",
        before="0 <= low", after="0 < low", line_hint=342,
        behaviour="port 0 abstains as though it were outside 0..65535. The chain "
                  "carries three `<=`, so the slice names the FIRST comparison",
        must_fail=(_TD + "test_port_zero_is_a_legal_port",),
        owner=_IOWNER),
    Mutation(
        id="MK-I12", module=_ID, enclosing="_port_bounds",
        before="high <= 65535", after="high <= 65536", line_hint=342,
        behaviour="the port upper bound is relaxed so the impossible port 65536 "
                  "is accepted instead of abstaining by name. Widened past the "
                  "bare 65535, which the abstention message spells too",
        must_fail=(_TD + "test_the_last_port_is_65535_and_one_past_it_abstains_by_name",),
        owner=_IOWNER),
    Mutation(
        id="MK-I13", module=_ID, enclosing="_guarded.extract",
        before="exc_info=True", after="exc_info=False", line_hint=548,
        behaviour="the extractor-failed debug record loses its traceback. SAME "
                  "TRAP as MK-P08: logging stores the literal False, so "
                  "`exc_info is not None` still passes -- only truthiness kills it",
        must_fail=(_TD + "test_a_crashing_domain_extractor_logs_its_traceback",),
        owner=_IOWNER),
    Mutation(
        id="MK-I14", module=_IS, enclosing="RuleContext",
        before="frozen=True", after="frozen=False", line_hint=112,
        behaviour="RuleContext stops being frozen, so a tier can mutate the one "
                  "record all three consult and it is no longer hashable",
        must_fail=(_TS + "test_rule_context_is_frozen_and_hashable",),
        owner=_IOWNER),
    Mutation(
        id="MK-I15", module=_IS, enclosing="CompiledRule.evaluate",
        before='                return Verdict("unverified", f"sec:{domain}", pid, 0,\n'
               '                               f"{pid}: z3 is not available (solver '
               'backend {backend!r}) — "',
        after='                return Verdict("unverified", f"sec:{domain}", pid, 1,\n'
              '                               f"{pid}: z3 is not available (solver '
              'backend {backend!r}) — "',
        line_hint=219,
        behaviour="the solver-not-available abstention points at line 1 of a "
                  "document that has no lines. Widened by its message line: the "
                  "not-evaluated abstention above it opens identically",
        must_fail=(_TS + "test_the_z3_absent_abstention_is_identified_and_carries_"
                         "no_line_number",),
        owner=_IOWNER),
)

#: DELIBERATELY EMPTY, and named rather than omitted: the removal set is split
#: out by ESC-GX-SEEDA-001 along with MK-I01..MK-I29, on the measured budget.
REMOVALS: tuple = ()
