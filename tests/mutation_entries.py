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

MK-I01..MK-I15 and then MK-I16..MK-I29 PLUS THE REMOVAL SET -- pieces (b) and
(c) of ESC-GX-SEEDA-001's measured three-way split, which landing CLOSES -- are
appended under those same rules, read from ``agent/gx-evidence-invokers``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path

from tests.mutation_contract import Mutation, Removal

_MOD = "gcp_grounding/preflight.py"
_OWNER = "gx-preflight-empty-key"
_T = "tests/test_gcp_preflight.py::"
_G = "tests/test_gcp_policy_gate.py::"

_IR, _ID = "gcp_grounding/registry.py", "gcp_grounding/sec_domains.py"
_IS, _IOWNER = "gcp_grounding/sec_rules.py", "gx-evidence-invokers"
_TR = "tests/test_gcp_registry.py::"
_TD = "tests/test_gcp_sec_domains.py::"
_TS = "tests/test_gcp_sec_rules.py::"
_TF = "tests/test_gcp_evidence_floor.py::"
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
    # -- ESC-GX-SEEDA-001 piece (c): the funnel's last fourteen. -------------
    Mutation(
        id="MK-I16", module=_IS, enclosing="CompiledRule._decide_closed",
        before='        return Verdict("contradicted", f"sec:{domain}", pid, 0,\n'
               '                       f"{pid}: the obligation is violated but no '
               'single record "',
        after='        return Verdict("contradicted", f"sec:{domain}", pid, 1,\n'
              '                       f"{pid}: the obligation is violated but no '
              'single record "',
        line_hint=264,
        behaviour="the lineno on \"the obligation is violated but no single "
                  "record witnesses it\", widened by its message line",
        must_fail=(_TS + "test_a_violation_no_single_record_witnesses_is_identified_"
                         "and_has_no_lineno",),
        owner=_IOWNER),
    Mutation(
        id="MK-I17", module=_IS, enclosing="CompiledRule._decide_open",
        before='            return Verdict("grounded", f"sec:{domain}", pid, 0,',
        after='            return Verdict("grounded", f"sec:{domain}", pid, 1,',
        line_hint=279,
        behaviour="the lineno on the open-or-validity grounded verdict",
        must_fail=(_TS + "test_the_validity_fallback_grounds_with_an_identity_and_"
                         "no_line_number",),
        owner=_IOWNER),
    Mutation(
        id="MK-I18", module=_IS, enclosing="_render_model",
        before="model_completion=True", after="model_completion=False",
        line_hint=332,
        behaviour="with completion off, unassigned terms render as bare symbol "
                  "names instead of concrete values, so a contradicted verdict's "
                  "counter-model stops being concrete evidence while still "
                  "reading like one",
        must_fail=(_TS + "test_a_counter_model_renders_a_value_for_every_term",),
        owner=_IOWNER),
    Mutation(
        id="MK-I19", module=_IS, enclosing="_org_constraint_name",
        before="name.split(marker, 1)", after="name.split(marker, 2)",
        line_hint=474,
        behaviour="the MAXSPLIT of the org-policy name split, not an index: with "
                  "maxsplit 2 a name containing two policy markers yields a "
                  "different constraint id",
        must_fail=(_TS + "test_the_constraint_id_is_the_whole_tail_after_the_"
                         "first_marker",),
        owner=_IOWNER),
    Mutation(
        id="MK-I20", module=_IS, enclosing="org_policy_rules",
        before="if not isinstance(policy, Mapping):",
        after="if isinstance(policy, Mapping):", line_hint=487,
        behaviour="CATASTROPHIC AND FREE TODAY: a VALID org policy returns "
                  "immediately with \"the Org Policy is not a JSON object\", so the "
                  "org-policy rule tier ALWAYS abstains. It survives because "
                  "nothing in the whole suite drives that tier with a real "
                  "org-policy document",
        must_fail=(_TS + "test_a_real_org_policy_yields_records_and_no_reason",),
        owner=_IOWNER),
    Mutation(
        id="MK-I21", module=_IS, enclosing="org_policy_rules",
        before='bool(rule.get("enforce", False))',
        after='bool(rule.get("enforce", True))', line_hint=507,
        behaviour="an ABSENT enforce key records enforce True — a silent inversion "
                  "of the org-policy enforcement dimension, which is decision-"
                  "relevant and is exactly the axis gx-org-prior-content reasons over",
        must_fail=(_TS + "test_an_absent_enforce_key_records_enforce_false",),
        owner=_IOWNER),
    Mutation(
        id="MK-I22", module=_IS, enclosing="org_policy_rules",
        before="if not isinstance(entry, str):",
        after="if isinstance(entry, str):", line_hint=521,
        behaviour="the surprise guard inverted, so string entries refuse and "
                  "non-string entries are appended into records",
        must_fail=(_TS + "test_a_list_of_strings_is_accepted_and_a_non_string_"
                         "entry_refuses",),
        owner=_IOWNER),
    Mutation(
        id="MK-I23", module=_IS, enclosing="_carry_verdict",
        before='        return Verdict("unverified", f"sec:{promise.domain}", '
               'promise.id, 0,',
        after='        return Verdict("unverified", f"sec:{promise.domain}", '
              'promise.id, 1,',
        line_hint=567,
        behaviour="the lineno on the not-run verdict for a rejected or failed "
                  "promise, sliced with the REJECTED arm's own indent",
        must_fail=(_TS + "test_a_carry_verdict_names_the_requirement_and_has_no_"
                         "line_number",),
        owner=_IOWNER),
    Mutation(
        id="MK-I24", module=_IS, enclosing="_admit",
        before='"integrity was not verified; the rule was registered")], True)',
        after='"integrity was not verified; the rule was registered")], False)',
        line_hint=595,
        behaviour="NOT a lineno: it is the REGISTER flag returned on the "
                  "unsupported-term path, whose own message says the rule WAS "
                  "registered. The mutant makes the message lie and silently "
                  "unregisters a rule whose stored AST cannot be re-encoded",
        must_fail=(_TS + "test_an_unsupported_term_registers_the_rule_its_message_"
                         "says_it_registered",),
        owner=_IOWNER),
    Mutation(
        id="MK-I25", module=_IS, enclosing="_admit",
        before="if positive_ok is None or negative_ok is None:",
        after="if positive_ok is None and negative_ok is None:", line_hint=616,
        behaviour="ONE undecidable pinned witness stops reporting \"a pinned "
                  "witness could not be re-classified\" and integrity reads as "
                  "fully verified — an abstention silently converted into a "
                  "positive, RC1's shape at the artifact tier",
        must_fail=(_TS + "test_one_undecidable_witness_is_reported_and_the_rule_"
                         "still_registers",),
        owner=_IOWNER),
    Mutation(
        id="MK-I26", module=_IS, enclosing="load_rules",
        before='        verdicts.append(Verdict("contradicted", "sec:artifact", pid, 0,',
        after='        verdicts.append(Verdict("contradicted", "sec:artifact", pid, 1,',
        line_hint=664,
        behaviour="the lineno on the duplicate-promise-id-across-artifacts verdict",
        must_fail=(_TS + "test_a_duplicate_promise_id_is_identified_and_has_no_"
                         "line_number",),
        owner=_IOWNER),
    Mutation(
        id="MK-I27", module=_IR, enclosing="_stands_on_nothing",
        before="led.collections_read > 0 and", after="led.collections_read > 0 or",
        line_hint=220,
        behaviour="the downgrade predicate THIS TASK writes — already killed by "
                  "this task's own tests. Named so it stays killed",
        must_fail=(_TF + "test_a_check_that_reads_nothing_is_not_downgraded",),
        owner=_IOWNER),
    Mutation(
        id="MK-I28", module=_IR, enclosing="_stands_on_nothing",
        before="led.rows_examined == 0", after="led.rows_examined == 1",
        line_hint=220,
        behaviour="the `rows_examined == 0` comparison in the same predicate, "
                  "which is also the REGISTERED predicate — already killed. "
                  "Named so it stays killed",
        must_fail=(_TF + "test_a_decision_over_an_empty_collection_is_downgraded",),
        owner=_IOWNER),
    Mutation(
        id="MK-I29", module=_IS, enclosing="CompiledRule._decide_closed",
        before='("; " + "; ".join(observed_empty))',
        after='("; " - "; ".join(observed_empty))', line_hint=248,
        behaviour="on the line this task writes in the compiled-rule tier — "
                  "already killed. Named so it stays killed",
        must_fail=(_TS + "test_attested_empty_collection_keeps_the_quantifier_"
                         "semantics",),
        owner=_IOWNER),
)


@dataclass(frozen=True)
class SeededRemoval(Removal):
    """The FROZEN ``Removal`` plus the three fields seed-a's body mandates and
    that type lacks -- ESC-GX-SEEDA-001's finding, answered by SUBCLASSING and
    never by dropping one. ``owner`` is REQUIRED: no family is parked forever."""

    owner: str = ""
    pending: bool = True
    spelling: str = ""


AFTER_COLLECTION = ("monkeypatched after collection; the family's cases keep "
                    "RUNNING and must FAIL on the verdicts that stop existing")
IMPORT_TIME = ("bound to None in sys.modules; its probes go false and its cases "
               "SKIP, so must_fail names the not-all-cases-may-skip guard and "
               "the capability-liveness assertion")
RE_MEASURED = ("bound to None in sys.modules AFTER collection, so the marks are "
               "already fixed and nothing skips; the two guards named below "
               "RE-MEASURE the probes instead of reading a memo taken before "
               "the removal, and both go RED when the plane cannot decide")


def _patch(monkeypatch, module: str, **fields) -> None:
    target = import_module(module)
    for name, value in fields.items():
        monkeypatch.setattr(target, name, value)


def _unimport(monkeypatch, *names: str) -> None:
    for name in names:
        monkeypatch.setitem(sys.modules, name, None)
    import_module("gcp_grounding.registry").reset_cache()


_AI = ("tests/test_gcp_agentic_iam.py::"
       "test_adversarial_proposal_is_blocked_or_recorded[")
_AN, _AV = "tests/test_gcp_agentic_network.py::", "tests/test_gcp_agentic_vpcsc.py::"
_AB = "tests/test_gcp_agentic_abstain.py::"

#: `gx-agentic-benign-repin`'s six, and the nodes each reddens.
_BG = "tests/test_gcp_agentic_benign.py::"
_BID = _BG + "test_spot_checked_turns_ground_the_claims_by_identity["
_BPAIR = _BG + "test_the_paired_hook_really_opened_that_path["
_BOWNER = "gx-agentic-benign-repin"
IN_PROCESS = ("monkeypatched after collection; the benign module's report and its "
              "hook MIRROR both run IN PROCESS, which is where a removal reaches "
              "them -- it can never reach a spawned child")


def _drop_claim_kind(monkeypatch, kind: str) -> None:
    """Take away exactly the claims of one KIND, at BOTH bindings: `preflight` and
    `tf_claims` each did `from .claims import iam_policy_claims`, so patching
    `claims` alone leaves the plan turn holding what the IAM turn lost."""
    real = import_module("gcp_grounding.claims").iam_policy_claims
    without = lambda policy: [c for c in real(policy) if c.kind != kind]  # noqa: E731
    for module in ("gcp_grounding.preflight", "gcp_grounding.tf_claims"):
        _patch(monkeypatch, module, iam_policy_claims=without)


def _drop_extractor(monkeypatch, rtype: str) -> None:
    """Empty ONE terraform resource type's extractor, leaving the walker's own
    unconditional `resource_type_ref` claim and nothing else -- the exact state
    the design measured a grounded-COUNT floor staying green over."""
    table = import_module("gcp_grounding.tf_claims")._EXTRACTORS
    _patch(monkeypatch, "gcp_grounding.tf_claims",
           _EXTRACTORS=dict(table, **{rtype: lambda address, values: []}))

#: The path ``RM-HOOK-WRONG-FILE``'s mutant grounds instead of the event's. A
#: repo-relative path that DOES NOT EXIST, so the hook reaches the gate, the
#: gate opens nothing, and the abstention it prints names this file and not the
#: one the agent edited -- the same answer on every backend.
_HARDCODED = str(Path(__file__).resolve().parents[1]
                 / "hardcoded_by_the_mutant.policy.json")

#: The RC2-measured removals: the review EXECUTED each -- 19 of 19, 27 of 27,
#: 22 of 27, 10 of 14 green with the subject GONE -- so each is a must-kill and
#: not a hypothesis. Each names the task that must make it live and whose body
#: requires the nodes that do not collect TODAY; the two `gx-agentic-iam-repin`
#: owns are LIVE, so the frozen gate EXECUTES them, and five stay `pending`.
REMOVALS: tuple[SeededRemoval, ...] = (
    SeededRemoval(
        id="RM-IAM-ESCALATION-LAYER", family="iam",
        subject="iam_checks.DOCUMENT_CHECKS, the escalation decision layer",
        apply=lambda mp: _patch(mp, "gcp_grounding.iam_checks", DOCUMENT_CHECKS=()),
        must_fail=(_AI + "A07_sa_token_creator]", _AI + "A08_sa_user_actas]",
                   _AI + "A09_owner_to_real_principal]"),
        owner="gx-agentic-iam-repin", pending=False, spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-IAM-PUBLIC-PRINCIPAL-KIND", family="iam",
        subject="the public_principal claim kind, dropped from claims.KINDS",
        apply=lambda mp: _patch(mp, "gcp_grounding.claims", KINDS=tuple(
            k for k in import_module("gcp_grounding.claims").KINDS
            if k != "public_principal")),
        must_fail=(_AI + "A11_allusers_public]",),
        owner="gx-agentic-iam-repin", pending=False, spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-NETWORK-PLANE-UNAVAILABLE", family="network",
        subject="fw_checks, fw_estate, hfw_checks and armor_checks — the whole "
                "network-plane check layer the catalogue is decided by",
        # armor_checks and fw_estate join the two the seed named. MEASURED on
        # HEAD's module: renaming all FOUR away leaves it 19 of 19 GREEN, which
        # is the defect; renaming only three leaves A01 still blocked by the
        # estate tier, and renaming only the seed's two leaves the armor
        # capability live, both guards passing, and the removal SURVIVING.
        #
        # STILL `pending`, and NOT because it does not kill: MEASURED both ways
        # in this checkout, both nodes report FAILED under the mutant and
        # PASSED on clean source. It cannot be flipped live from here on the
        # SPAWN CEILING alone -- ESC-GX-NETWORK-REMOVAL-CEILING, which carries
        # the arithmetic.
        apply=lambda mp: _unimport(mp, "gcp_grounding.fw_checks",
                                   "gcp_grounding.fw_estate",
                                   "gcp_grounding.hfw_checks",
                                   "gcp_grounding.armor_checks"),
        must_fail=(_AN + "test_not_every_network_case_may_skip",
                   _AN + "test_the_network_capabilities_are_live"),
        owner="gx-agentic-network-repin", spelling=RE_MEASURED),
    SeededRemoval(
        id="RM-NETWORK-PAIR-CHECKS", family="network",
        subject="fw_checks.PAIR_CHECKS, the packet-set non-enlargement map",
        apply=lambda mp: _patch(mp, "gcp_grounding.fw_checks", PAIR_CHECKS={}),
        must_fail=(_AN + "test_the_pair_check_decides_a_widening_against_a_"
                         "baseline",),
        owner="gx-agentic-network-repin", pending=False,
        spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-NETWORK-VOCABULARY-KIND", family="network",
        subject="the resource_type verdict kind, renamed where the Datalog "
                "pass maps a claim kind to its snapshot category",
        apply=lambda mp: _patch(
            mp, "gcp_grounding.reasoner",
            _CLAIM_CATEGORIES=dict(
                import_module("gcp_grounding.reasoner")._CLAIM_CATEGORIES,
                resource_type_ref="resource_kind")),
        must_fail=(_AN + "test_the_false_vocabulary_block_guard_can_fire_and_"
                         "is_silent",),
        owner="gx-agentic-network-repin", pending=False,
        spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-VPCSC-DOCUMENT-AND-PAIR-CHECKS", family="vpcsc",
        subject="vpcsc_checks.DOCUMENT_CHECKS and PAIR_CHECKS, unregistered",
        apply=lambda mp: _patch(mp, "gcp_grounding.vpcsc_checks",
                                DOCUMENT_CHECKS=(), PAIR_CHECKS={}),
        # RETARGETED ON MEASUREMENT, never widened: the seed named A05, A24 and
        # A25, and all three drive the gate in a CHILD process, which an
        # after-collection monkeypatch of the parent cannot reach -- measured,
        # all three still PASSED with both tables emptied. The three nodes below
        # ground IN PROCESS, one per half of what this removal takes: the pair
        # check, the document check's estate arm, and its solver arm.
        must_fail=(_AV + "test_the_pair_check_decides_a_removal_against_a_"
                         "baseline",
                   _AV + "test_an_uncaptured_perimeter_category_abstains_once_"
                         "per_perimeter",
                   _AV + "test_a_widening_against_a_narrow_previous_policy_is_"
                         "decided"),
        owner="gx-agentic-vpcsc-repin", spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-VPCSC-DOMAIN-UNREGISTERED", family="vpcsc",
        subject="the whole VPC-SC domain: vpcsc_checks and vpcsc_claims",
        apply=lambda mp: _unimport(mp, "gcp_grounding.vpcsc_checks",
                                   "gcp_grounding.vpcsc_claims"),
        must_fail=(_AV + "test_not_every_vpcsc_case_may_skip",
                   _AV + "test_the_vpcsc_capabilities_are_live"),
        owner="gx-agentic-vpcsc-repin", spelling=IMPORT_TIME),
    SeededRemoval(
        id="RM-VPCSC-ABSENT-VERSUS-EMPTY", family="vpcsc",
        subject="vpcsc_checks._unreadable_field, the record-level "
                "absent-versus-empty guard",
        apply=lambda mp: _patch(mp, "gcp_grounding.vpcsc_checks",
                                _unreadable_field=lambda *a, **k: None),
        must_fail=(_AV + "test_a_removed_policy_list_yields_the_absent_versus_"
                         "empty_abstention",),
        owner="gx-agentic-vpcsc-repin", spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-HOOK-SUCCESS-BEFORE-THE-EVENT", family="abstain",
        subject="cli._run_hook: the hook returns success as its FIRST "
                "statement, never reading the event",
        apply=lambda mp: _patch(mp, "gcp_grounding.cli", _run_hook=lambda args: 0),
        # MEASURED BOTH WAYS in this checkout. Before `gx-agentic-abstain-repin`
        # this removal killed NOTHING: every one of the module's 14 cases drove
        # the hook in a CHILD process, which an after-collection monkeypatch of
        # the PARENT cannot reach, so all 14 PASSED with the subject gone. The
        # repin gives every case an IN-PROCESS mirror of the same
        # `cli._run_hook`, and under the mutant all three nodes below now report
        # FAILED and all three PASS on clean source.
        #
        # STILL `pending`, and NOT because it does not kill:
        # `contract_spawn_ceiling()` is `4*len(register()) +
        # len(removal_register()) + CONTRACT_CONTROL_SPAWNS`, and a full run
        # measures the marked total at exactly the ceiling. A NEW live removal
        # is net zero (one slot, one `-rA` child); flipping an ALREADY-COUNTED
        # one from pending to live is +1 spawn and +0 slots, so it overflows by
        # exactly one whatever else the diff does. This task's NEW removal below
        # is therefore the live one -- ESC-GX-ABSTAIN-REMOVAL-CEILING carries
        # the arithmetic, exactly as ESC-GX-NETWORK-REMOVAL-CEILING does.
        must_fail=(_AB + "test_c01_raw_hcl_abstains_and_never_blocks",
                   _AB + "test_c04_unrecognized_kind_abstains_naming_the_keys",
                   _AB + "test_c08_uncaptured_category_is_unverified_never_ungrounded"),
        owner="gx-agentic-abstain-repin", spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-HOOK-WRONG-FILE", family="abstain",
        subject="cli._hook_file_path: the hook ignores the event's path and "
                "grounds a hardcoded one instead",
        # The second mutant `gx-agentic-abstain-repin` records: a hook that
        # never reads the event's `file_path` still exits 0 with byte-empty
        # stdout and still abstains -- about a document nobody edited -- which
        # left 11 of that module's 14 cases green before the repin. The
        # hardcoded path is deliberately one that does not exist, so the mutant
        # is world-independent: the gate opens it, fails to READ it, and prints
        # a reason no case here asks for, whatever the solver backend is.
        apply=lambda mp: _patch(mp, "gcp_grounding.cli",
                                _hook_file_path=lambda event: _HARDCODED),
        must_fail=(_AB + "test_c01_raw_hcl_abstains_and_never_blocks",
                   _AB + "test_c04_unrecognized_kind_abstains_naming_the_keys",
                   _AB + "test_c08_uncaptured_category_is_unverified_never_ungrounded",
                   _AB + "test_a_document_whose_grants_were_never_read_is_not_a_"
                         "verdictless_pass[bindings_key_mis_cased]",
                   _AB + "test_c10_bad_baseline_abstains_on_the_subset"
                         "[nonexistent_path]"),
        owner="gx-agentic-abstain-repin", pending=False,
        spelling=AFTER_COLLECTION),
    # THE FIVE CLAIM-EXTRACTION DELETIONS AND THE EMPTIED HOOK SUFFIX SET, the six
    # `gx-agentic-benign-repin` measured. BEFORE that repin all six left
    # tests/test_gcp_agentic_benign.py GREEN -- 19 of 19 passed, each mutant applied
    # alone to a `git archive HEAD` copy -- because the spot-checks asserted a
    # grounded COUNT and the hook was asserted only for silence. AFTER it each node
    # below reports FAILED and every one PASSES on clean source. All six are LIVE:
    # a NEW live removal is one slot and one `-rA` child, net zero on
    # `contract_spawn_ceiling()`, so none of them needs the flip
    # ESC-GX-ABSTAIN-REMOVAL-CEILING records as unaffordable.
    SeededRemoval(
        id="RM-BENIGN-PLAN-MEMBER-EXTRACTION", family="iam",
        subject="the plan walker's whole role and principal extraction for "
                "google_project_iam_member",
        apply=lambda mp: _drop_extractor(mp, "google_project_iam_member"),
        must_fail=(_BID + "B06_tfplan_iam_member]",
                   _BPAIR + "B06_tfplan_iam_member]"),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
    SeededRemoval(
        id="RM-BENIGN-ROLE-CLAIMS", family="iam",
        subject="every role claim an IAM policy makes, at both extractor bindings",
        apply=lambda mp: _drop_claim_kind(mp, "role"),
        must_fail=(_BID + "B02_iam_grant_data_eng]",
                   _BID + "B06_tfplan_iam_member]"),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
    SeededRemoval(
        id="RM-BENIGN-PRINCIPAL-CLAIMS", family="iam",
        subject="every principal claim an IAM policy makes, at both bindings",
        apply=lambda mp: _drop_claim_kind(mp, "principal"),
        must_fail=(_BID + "B02_iam_grant_data_eng]",
                   _BID + "B06_tfplan_iam_member]"),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
    SeededRemoval(
        id="RM-BENIGN-CUSTOM-ROLE-PERMISSIONS", family="iam",
        subject="every permission claim a google_project_iam_custom_role makes",
        apply=lambda mp: _drop_extractor(mp, "google_project_iam_custom_role"),
        must_fail=(_BID + "B07_tfplan_custom_role]",),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
    SeededRemoval(
        id="RM-BENIGN-CONSTRAINT-EXISTENCE", family="orgpolicy",
        subject="the constraint-existence claim an org policy makes, leaving only "
                "its value-type one",
        apply=lambda mp: _patch(
            mp, "gcp_grounding.preflight",
            org_policy_claims=lambda policy: [
                c for c in import_module("gcp_grounding.claims").org_policy_claims(
                    policy) if c.kind != "constraint"]),
        must_fail=(_BID + "B04_orgpolicy_shielded_vm]",),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
    SeededRemoval(
        id="RM-BENIGN-HOOK-SUFFIXES", family="abstain",
        subject="cli._HOOK_SUFFIXES: the hook recognizes no file as a policy "
                "document, so it grounds nothing and can never block",
        apply=lambda mp: _patch(mp, "gcp_grounding.cli", _HOOK_SUFFIXES=()),
        must_fail=(_BPAIR + "B02_iam_grant_data_eng]",
                   _BPAIR + "B04_orgpolicy_shielded_vm]",
                   _BPAIR + "B06_tfplan_iam_member]"),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
)
